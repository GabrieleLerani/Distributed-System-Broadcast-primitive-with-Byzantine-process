import socket
import hashlib
import hmac
import json
import logging
from threading import Thread
import threading

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

RCV_BUFFER_SIZE = 1024
KEY_SIZE = 32


class AuthenticatedLink:
    def __init__(self, self_id, self_ip, idn, ip, proc):
        self.proc = proc
        self.self_id = self_id  # id of sending process
        self.id = idn  # id of receiving process
        self.self_ip = self_ip
        self.ip = ip
        self.key = {}
        self.lock = threading.Lock()   # TODO remove once it is not useful anymore

    def get_id(self):
        return self.id

    def receiver(self):
        print("Start thread to receive messages...")
        t = Thread(target=self.__receive)
        t.start()

    # This handles the message receive
    # Now the listening port is the concatenation 50/5 - 'receiving process' - 'sending process'
    def __receive(self):
        ready = False
        host = ""  # Symbolic name meaning all available interfaces
        # It uses ternary operator
        port = (
            int("50" + str(self.id) + str(self.self_id))
            if self.self_id < 10 and self.id < 10
            else int("5" + str(self.id) + str(self.self_id))
        )

        print(port)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.s:
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.s.bind((host, port))
            self.s.listen(0)
            while True:
                conn, addr = self.s.accept()

                with conn:
                    while True:
                        data = conn.recv(RCV_BUFFER_SIZE)
                        if not data:
                            break

                        parsed_data = json.loads(data.decode())

                        self.lock.acquire()
                        print("Message received by ", self.ip, ":", parsed_data)
                        self.lock.release()

                        if "Flag" not in parsed_data.keys():
                            self.__add_key(parsed_data)
                            conn.sendall(b"synACK")
                        else:
                            t = Thread(
                                target=self.__receiving,
                                args=(parsed_data,),
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
                            if "ACC" in parsed_data.values():
                                ready = True

                if ready:
                    break

    def __add_key(self, key_dict):
        self.key[self.id] = key_dict["KEY"].encode("latin1")

        logging.info(
            "AUTH: <%s, %d> is the one with this key: %s", self.ip, self.id, self.key
        )

    def __check(self, idn):
        if idn not in self.key:
            self.key[idn] = ChaCha20Poly1305.generate_key()

            key_to_send = {"KEY": self.key[idn].decode("latin1")}
            logging.info("AUTH: Key generated")

            data = json.dumps(key_to_send)
            self.sock.sendall(data.encode())
            self.temp = self.sock.recv(RCV_BUFFER_SIZE, 0).decode()

            if self.temp != "synACK":  # Ack used for synchronization with other process
                return 1

    # Compute the hmac of the message with a key associated to the process with self.id
    # The message is returned as a dictionary: {"MSG": message,"HMAC": hmac, "FLAG": flag}
    # The hmac is computed starting from the concatenation of flag and message
    # Example: flag = "SEND" , message = "Hello" ----> HMAC("SENDHello")
    def __auth(self, message):
        self.__check(self.id)
        mess = {
            "Flag": message["Flag"], "Source": message["Source"], "Message": message["Message"],
            "SequenceNumber": message["SequenceNumber"], "HMAC": hmac.new(
                self.key.get(self.id, "Key not found"),
                (message["Flag"] + str(message["Source"]) + message["Message"] + str(message["SequenceNumber"]))
                .encode("utf-8"), hashlib.sha256,
            ).hexdigest(),
        }
        return mess

    # The SEND opens a new socket, the port is the concatenation of 50/5-
    # id of sending process - id of receiving process
    # Example: sending_id = 1, receiving_id = 2 ---> port = 5012
    def send(self, message):
        # It uses ternary operator
        port = (
            int("50" + str(self.self_id) + str(self.id))
            if self.self_id < 10 and self.id < 10
            else int("5" + str(self.self_id) + str(self.id))
        )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.connect((self.ip, port))

            # mess is a dictionary that contains the original packet plus the HMAC
            mess = self.__auth(message)

            self.lock.acquire()
            print(mess, "sent to <", self.ip, self.id, ">")
            self.lock.release()

            parsed_data = json.dumps(mess)
            self.sock.sendall(bytes(parsed_data, encoding="utf-8"))

    # It checks message authenticity comparing the hmac
    def __check_auth(self, message):
        temp_hash = hmac.new(
            self.key.get(self.id, "Key not found"),
            (message["Flag"] + str(message["Source"]) + message["Message"] + str(message["SequenceNumber"])).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return temp_hash == message["HMAC"]

    def __receiving(self, message):
        flag = message["Flag"]

        if not self.__check_auth(message):
            logging.info("--- Authenticity check failed for %s", message)
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