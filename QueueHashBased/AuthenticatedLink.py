import hashlib
import hmac
import ast
import threading

import pika
from threading import Thread

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

RCV_BUFFER_SIZE = 1024
KEY_SIZE = 32
SERVER_IP = "192.168.1.41"


class AuthenticatedLink:
    def __init__(self, self_id, self_ip, idn, ip, proc):
        self.proc = proc
        self.self_id = self_id  # id of sending process
        self.id = idn  # id of receiving process
        self.self_ip = self_ip
        self.ip = ip
        self.key = {}
        self.barrier = threading.Barrier(parties=2)

    def get_id(self):
        return self.self_id

    def receiver(self):
        print("Start thread to receive messages...")
        t = Thread(target=self.__receive)
        t.start()

    # This handles the message receive
    def __receive(self):
        # The queue name is the concatenation of the sender id and the receiver id
        queue_id = str(self.id) + str(self.self_id)

        with pika.BlockingConnection(pika.ConnectionParameters(host=SERVER_IP)) as connection:
            channel = connection.channel()
            channel.queue_declare(queue=queue_id)

            def callback(ch, method, properties, body):
                queue_msg = body.decode("utf-8")

                print("Message received by ", self.ip, ":", queue_msg)

                msg_dict = ast.literal_eval(queue_msg)

                if "ACK" in msg_dict.keys():
                    self.barrier.wait()   # used to synchronize it with the check function
                elif "Flag" not in msg_dict.keys():
                    self.__add_key(msg_dict)
                    self.send({"ACK": "synACK"})
                else:
                    t = Thread(
                        target=self.__receiving,
                        args=(msg_dict,),
                    )
                    t.start()
                    # if you receive an ACC for some message M from some other process,
                    # it means that it received at least n-f ECHOs for that message M,
                    # so it is safe to close the socket with it
                    # (it received at least f+1 ECHOs from correct processes,
                    # so it is impossible that it will send a REQ message;
                    # in fact, even if it receives the same message from all the faulty processes
                    # it will not send it because they are at most f)
                    # Otherwise, if you don't receive an ACC from someone,
                    # it may mean that it did not receive the message at all,
                    # so it may ask you about the message associated to the ACC that it received
                    # (indeed, you will send / sent an ACC message to it too)
                    if "ACC" in msg_dict.values():
                        channel.stop_consuming()
                        channel.close()

            channel.basic_consume(
                queue=queue_id, on_message_callback=callback, auto_ack=True
            )
            channel.start_consuming()

    def __add_key(self, key_dict):
        self.key[self.id] = key_dict["KEY"].encode("latin1")

    def __check(self, idn):
        if idn not in self.key:
            self.key[idn] = ChaCha20Poly1305.generate_key()
            key_to_send = {"KEY": self.key[idn].decode("latin1")}
            # The queue name is the concatenation of the sender id and the receiver id
            # Same as before but they are in reverse order because now this process is the sender
            queue_id = str(self.self_id) + str(self.id)

            connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=SERVER_IP))  # Connect to CloudAMQP
            channel = connection.channel()  # start a channel
            channel.queue_declare(queue=queue_id)  # naming queue
            channel.basic_publish(exchange='', routing_key=queue_id,
                                  body=str(key_to_send).encode("utf-8"))
            connection.close()  # closing connection

            # used to synchronize with the __receive function in order not to
            # go on without being sure the counterpart has received the key
            self.barrier.wait()

    # Compute the hmac of the message with the key exchanged
    # The message is returned as a dictionary: {"FLAG": flag, "MSG": message, ... "HMAC": hmac}
    # The hmac is computed starting from the concatenation of all the fields in the message
    def __auth(self, message):
        self.__check(self.id)
        # This creates the string that will be authenticated
        hmac_input = ""
        for value in message.values():
            hmac_input += str(value)
        # This creates the message that will be sent
        mess = {}
        dict_hmac = {"HMAC": hmac.new(
            self.key.get(self.id, "Key not found"), hmac_input.encode("utf-8"), hashlib.sha256, ).hexdigest(),
                     }
        for key in message.keys():
            dict_temp = {key: message[key]}  # Adding to the dictionary all the field that
            mess.update(dict_temp)  # were inside the original message
        mess.update(dict_hmac)  # Adding to it the HMAC just computed
        return mess

    def send(self, message):
        # The queue name is the concatenation of the sender id and the receiver id
        # Same as before but they are in reverse order because now this process is the sender
        queue_id = str(self.self_id) + str(self.id)
        mess = self.__auth(message)
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=SERVER_IP))  # Connect to CloudAMQP
        channel = connection.channel()  # start a channel
        channel.queue_declare(queue=queue_id)  # naming queue
        channel.basic_publish(exchange='', routing_key=queue_id,
                              body=str(mess).encode("utf-8"))
        connection.close()  # closing connection

    # It checks message authenticity comparing the hmac
    def __check_auth(self, message):
        # This creates the string that should match with the HMAC
        hmac_input = ""
        for value in message.values():
            hmac_input += str(value)
        temp_hash = hmac.new(
            self.key.get(self.id, "Key not found"), hmac_input.encode("utf-8"), hashlib.sha256,
        ).hexdigest()
        # The HMAC field is always present in the Authenticated Link implementation
        return temp_hash == message["HMAC"]

    def __receiving(self, message):
        flag = message["Flag"]

        if not self.__check_auth(message):
            pass
            # TODO what do if authenticity check fails??

        # this is done in order to pass to the upper layer only the part that it requires
        # indeed, the HMAC is removed because it is useful only for this level
        message.pop("HMAC", None)

        if flag == "MSG":
            self.proc.receiving_msg(message, self.id)
        elif flag == "ECHO":
            self.proc.receiving_echo(message, self.id)
        elif flag == "ACC":
            self.proc.receiving_acc(message, self.id)
        elif flag == "REQ":
            self.proc.receiving_req(message, self.id)
        elif flag == "FWD":
            self.proc.receiving_fwd(message, self.id)
