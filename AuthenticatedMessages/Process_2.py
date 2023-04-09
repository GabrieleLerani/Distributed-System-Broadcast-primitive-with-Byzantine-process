import math
import Link
import pika as pika
import socket
from threading import Thread
import json
import struct
import time
import logging
# import threading
# from Crypto.PublicKey import RSA
from sys import platform
from hashlib import sha512
import Authenticated_Link

SERVER_ID = "192.168.1.11"
SERVER_PORT = 5000

KDS_IP = '192.168.1.11'
KDS_PORT = 8080

RCV_BUFFER_SIZE = 1024
BREAK_TIME = 0.1

BROADCASTER_ID = 1

PLACEHOLDER = "vote_msg"


class Process:
    def __init__(self):
        self.ids = []
        self.ips = []
        self.signed_vote_messages_container = [{}]
        self.sip = 0
        self.sid = 0
        self.L = []
        self.AL = []
        self.start = 0
        self.key_gen = False
        self.keyPair = {}
        self.public_keys = {}
        self.delivered = False
        self.f = math.floor(len(self.ids) / 3)  # f<N/3 condition to protocol correctness

    def connection_to_server(self):
        # It starts a connection to the server to obtain a port number
        print("-----CONNECTING TO SERVER...-----")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.connect((SERVER_ID, SERVER_PORT))
            mess = bytes("Hello", "utf-8")
            s.sendall(mess)
            data = s.recv(RCV_BUFFER_SIZE).decode()
            # print(sys.stderr, "This is the port given by the server: " + data)
            logging.debug("PROCESS:This is the port given by the server: %s", data)
        port = 5000 + int(data)
        print("-----CONNECTION TO SERVER SUCCESSFULLY CREATED-----")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.connect((SERVER_ID, port))
            mess = bytes("Hello", "utf-8")
            sock.sendall(mess)
            while True:
                # receive the length prefix (4 bytes in network byte order)
                len_prefix = sock.recv(4)
                if not len_prefix:
                    break

                # unpack the length prefix into an integer
                msg_len = struct.unpack("!I", len_prefix)[0]
                # receive the JSON object data
                json_data = b""
                while len(json_data) < msg_len:
                    packet = sock.recv(msg_len - len(json_data))
                    if not packet:
                        break
                    json_data += packet

                # parse the JSON object
                obj = json.loads(json_data.decode("utf-8"))

                # Add IP and ID to list
                if isinstance(obj, dict):
                    self.ids.append(obj.get("ID", "Not found"))
                    self.ips.append(obj.get("IP", "Not found"))
                # END is str so isinstance of obj returns false
                else:
                    break

        logging.debug("PROCESS: id list: %s,ip list %s", self.ids, self.ips)
        logging.info("PROCESS:Starting thread on function thread")
        print("-----GATHERED ALL THE PEERS IPS FROM THE BOOTSTRAP SERVER-----")
        print("-----STARTING SENDING OR RECEIVING MESSAGES-----")

    def creation_links(self):
        # binding my information

        # checking os

        hostname = socket.gethostname()

        IPAddr = socket.gethostbyname(hostname)
        self.sip = IPAddr
        self.sid = self.ids[self.ips.index(self.sip)]
        # creating links
        for i in range(0, len(self.ids)):
            # init links
            self.L.append(
                Link.Link(
                    self.sid, self.sip, self.ids[i], self.ips[i], self,
                )
            )
            # setting up links
            self.L[i].build_Link_r()
            self.L[i].build_Link_s()
        for i in range(0, len(self.ids)):
            self.AL.append(
                Authenticated_Link.AuthenticatedLink(
                    self.sid, self.sip, self.ids[i], self.ips[i], self
                )
            )
            self.AL[i].receiver()
        logging.info("PROCESS:links successfully created")
        # init data structure for process's links and signed vote messages

        for p in range(1, len(self.ids) + 1):
            self.signed_vote_messages_container.append({})

            for id in range(1, len(self.ids) + 1):
                self.signed_vote_messages_container[p][str(id)] = {}
        logging.info("PROCESS:data structures for processes successfully created")
        t = Thread(target=self.listening_thread)
        t.start()

    def listening_thread(self):
        # checking for condition assuming only one broadcast round
        i = 1
        checked_indexes=[]
        while True:
            if i not in checked_indexes and i in range(1, len(self.ids) +1):
                final_msg_dict = self.count(i)
                final_msg_dict['TYPE'] = 2
                final_msg_dict['FROM'] = str(self.sid)
                if final_msg_dict.get('GO'):

                    for j in range(0, len(self.ids)):
                        self.L[j].link_send(final_msg_dict)
                        logging.info("PROCESS:signed vote messages:%s,broadcasted successfully",
                                     final_msg_dict.get('MSG'))

                    self.deliver(final_msg_dict['MSG'])
                    logging.info("PROCESS:-----ENDING PROTOCOL--> AUTHENTICATED MESSAGES BROADCAST-----")
                    logging.info("PROCESS:-----SUCCESSFULL EXIT-----")
                    for j in range(0, len(self.ids)):
                        self.L[j].ts.terminating_flag = True
                        self.L[j].td.terminating_flag = True
                    for j in range(0,len(self.ids)):
                        self.AL[j].s.close()

                    exit(0)

                if len(self.signed_vote_messages_container[i]) != 0:
                    checked_indexes.append(i)
            time.sleep(BREAK_TIME)
            i = i + 1
            if i == len(self.ids)+1:
                i = 1
                checked_indexes=[]

    def __update(self):
        with pika.BlockingConnection(
                pika.ConnectionParameters(host=SERVER_ID)
        ) as connection:
            channel = connection.channel()

            response = channel.queue_declare(queue=str(self.sid))
            # Get the queue length (number of not consumed messages)
            num = response.method.message_count

            logging.info(
                "PROCESS: %d,%s --- My queue length: %d", self.sid, self.sip, num
            )

            if num == 0:
                channel.close()
                return

            self.counter = 0

            def callback(ch, method, properties, body):
                logging.info("PROCESS: [x] Received %r", body)
                queue_msg = body.decode("utf-8")
                temp = queue_msg.split("#")
                ip_from_queue = temp[0]
                id_from_queue = temp[1]
                if ip_from_queue not in self.ips:
                    self.signed_vote_messages_container.append({})
                    print(self.ids)
                    for id in range(1, len(self.ids) + 2):
                        self.signed_vote_messages_container[int(id_from_queue)][str(id)] = {}
                        print(id)

                    logging.info("PROCESS:data structures for new incoming process successfully created")
                    # updating all the other processes data structure

                    for p in range(1, len(self.ids) + 2):
                        self.signed_vote_messages_container[p][str(id_from_queue)] = {}
                    logging.info("PROCESS:data structures of processes for new incoming process successfully updated")

                    self.ips.append(ip_from_queue)
                    self.ids.append(int(id_from_queue))
                    self.L.append(
                        Link.Link(
                            self.sid,
                            self.sip,
                            self.ids[len(self.ids) - 1],
                            self.ips[len(self.ips) - 1],
                            self,
                        )
                    )
                    self.AL.append(
                        Authenticated_Link.AuthenticatedLink(
                            self.sid,
                            self.sip,
                            self.ids[len(self.ids) - 1],
                            self.ips[len(self.ips) - 1],
                            self,
                        )
                    )
                    self.AL[len(self.AL) - 1].receiver()
                    self.L[len(self.L) - 1].build_Link_r()
                    self.L[len(self.L) - 1].build_Link_s()
                    # init data structure for process's link
                    logging.info("PROCESS:links for new incoming process successfully created")


                self.counter += 1
                if self.counter == num:
                    channel.stop_consuming()
                    channel.close()

            channel.basic_consume(
                queue=str(self.sid), on_message_callback=callback, auto_ack=True
            )
            channel.start_consuming()

    def broadcast(self, message):
        # broadcasting messages to all processes
        self.__update()  # updating receiving side links
        msg_temp = ""
        # marshal message
        if self.start == 0 and self.sid == BROADCASTER_ID:
            mess = {}
            mess['TYPE'] = 0
            msg_temp = message
            message = mess
            self.start = 1
            logging.info("PROCESS:marshalling first broadcast message for the broadcaster")

        if message.get('TYPE') == 0:
            msg = {}
            msg['TYPE'] = 0
            msg['FLAG'] = "PROPOSE"
            msg['MSG'] = msg_temp
            msg['FROM'] = BROADCASTER_ID

            for j in range(0, len(self.ids)):
                self.AL[j].send(msg)
            #self.barrier.wait()  # to remain consistent
            logging.info("PROCESS:Message:%s,broadcasted successfully", message)
        else:
            logging.info("PROCESS:ERROR:Cannot send a message of type undefined")

    def process_receive(self, message):
        # receive messages from the underlying pppl
        match message.get('TYPE'):
            case 0:
                logging.info("PROCESS:Received a message of type 0")

                if message.get('FROM') == BROADCASTER_ID and message.get('FLAG') == "PROPOSE":
                    # self.broadcast(msg)
                    msg = {}
                    msg['FLAG'] = "VOTE"
                    msg['MSG'] = message.get('MSG')
                    msg['SIGN'] = self.make_signature(msg.get('FLAG') + msg.get('MSG'))
                    msg['TYPE'] = 1
                    msg['FROM'] = self.sid

                    for j in range(0, len(self.ids)):
                        self.L[j].link_send(msg)
                    logging.info("PROCESS:Vote message:%s,broadcasted successfully", msg)

                else:
                    if message.get('FLAG') != "VOTE":
                        logging.info("PROCESS:Wrong flag received %s", message.get('FLAG'))

                    else:
                        logging.info("PROCESS:Authentication error")

            case 1:
                logging.info("PROCESS:Received a message of type 1")

                if message.get('FLAG') == "VOTE" and self.check_signature(message.get('FLAG') + message.get('MSG'), message.get('SIGN'),
                                                                      message.get('FROM')):
                    self.signed_vote_messages_container[self.sid][str(message.get('FROM'))][message.get('MSG')] = message.get(
                        'MSG')
                    self.signed_vote_messages_container[self.sid][str(message.get('FROM'))][
                        str(message.get('MSG')) + 'SIGN'] = message.get('SIGN')
                else:
                    if message.get('FLAG') != "VOTE":
                        logging.info("PROCESS:Wrong flag received %s", message.get('FLAG'))
                    else:
                        logging.info("PROCESS:Authentication error")

            case 2:
                logging.info("PROCESS:Received a message of type 2")
                counter = 0

                if not self.delivered:

                    for id in message['keys'].keys():
                        if PLACEHOLDER not in id:
                            if self.check_signature(message['keys'][str(id) + PLACEHOLDER]['MSG'],
                                                    message['keys'][str(id) + PLACEHOLDER]['SIGN'], str(id)):
                                counter = counter + 1
                            if counter == (len(self.ids) - self.f):
                                self.deliver(message['MSG'])
                else:
                    logging.info("PROCESS:Already delivered not re-broadcast all the signed vote messages")
            case _:
                logging.info("PROCESS:ERROR:Received a message of type undefined")

    def check_signature(self, message, signature, idn):
        # checking signature for received signed vote messages
        if str(idn) not in self.public_keys.keys():  # maybe list
            logging.info("PROCESS:Calling KDS to get public key")
            self.public_keys[str(idn)] = {}  # initialize dictionary for public keys of process id=idn
            temp_dict = self.connection_to_KDS(idn, 0)
            self.public_keys[str(idn)]['N'] = temp_dict['KEY']['N']
            self.public_keys[str(idn)]['E'] = temp_dict['KEY']['E']

        msg = bytes(message, 'utf-8')
        hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
        hashFromSignature = pow(signature, self.public_keys[str(idn)]['E'], self.public_keys[str(idn)]['N'])
        logging.info("PROCESS:Signature check exit:<%r>", hash == hashFromSignature)
        return hash == hashFromSignature

    def make_signature(self, message):
        # generating keys
        if not self.key_gen:
            logging.info("PROCESS:Calling KDS to get key pair")
            self.key_gen = True
            self.keyPair = self.connection_to_KDS(self.sid, 1)
        else:
            logging.info("PROCESS:Key already generated")
        # sign
        msg = bytes(message, 'utf-8')
        hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
        signature = pow(hash, self.keyPair['D'], self.keyPair['N'])
        logging.info("PROCESS:Signature:<%s>", hex(signature))
        return signature

    def connection_to_KDS(self, idn, typ):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.connect((KDS_IP, KDS_PORT))
            logging.info("PROCESS:Connecting to KDS")
            # getting key pair from KDS
            pack = {}
            pack['FROM'] = idn
            pack['TYPE'] = typ
            send_pack = json.dumps(pack)
            sock.sendall(send_pack.encode())
            data = sock.recv(RCV_BUFFER_SIZE)
            parsed_data = json.loads(data.decode())
            # return a dict containing
            return parsed_data

    def count(self, i):
        # counting if a safe vote message sats the condition
        current_dict = {}

        checked_msgs = []
        for id in self.signed_vote_messages_container[i]:  # checking for all processes id that sent to i a message
            counter = 0
            current_dict = {}  # container
            current_dict[
                'keys'] = {}  # container into the current_dict container that contains keys_id of the processes that actually signed this current msg to be delivered
            counter = 0
            current_dict['GO'] = False  # barrier flag to go ahead or not
            current_values=[]
            for k in self.signed_vote_messages_container[i][
                str(id)].keys():
                if 'SIGN' not in k:
                    current_values.append(k)
            # listing messages received from id
            for current_msg in current_values:  # choosing one message received from id
                if current_msg not in checked_msgs:
                    counter = 1
                    current_dict['MSG'] = current_msg
                    current_dict['keys'][str(id)] = str(id)
                    current_dict['keys'][
                        str(id) + PLACEHOLDER] = {}  # new dict for each id to know the pair <msg,signed_msg>; the +vote_msg string to avoid overwriting the prec line
                    current_dict['keys'][str(id) + PLACEHOLDER]['MSG'] = current_msg
                    current_dict['keys'][str(id) + PLACEHOLDER]['SIGN'] = self.signed_vote_messages_container[i][str(id)][
                        current_msg + 'SIGN']

                    for id2 in self.signed_vote_messages_container[i]:  # choosing another process different from id
                        if id2 != id:
                            current_values2 = []
                            for f in self.signed_vote_messages_container[i][
                                str(id2)].keys():
                                if 'SIGN' not in f:
                                    current_values2.append(f)
                            for other_msg in current_values2:  # checking one message between those that process id2 sent to i
                                if current_msg == other_msg:
                                    current_dict['keys'][str(id2)] = str(id2)
                                    current_dict['keys'][
                                        str(id2) + PLACEHOLDER] = {}  # new dict for each id to know the pair <msg,signed_msg>; the +vote_msg string to avoid overwriting the prec line
                                    current_dict['keys'][str(id2) + PLACEHOLDER]['MSG'] = other_msg
                                    current_dict['keys'][str(id2) + PLACEHOLDER]['SIGN'] = self.signed_vote_messages_container[i][str(id2)][other_msg + 'SIGN']
                                    counter = counter + 1
                                if counter == (len(self.ids) - self.f):
                                    current_dict['GO'] = True
                                    return current_dict
                        elif len(self.ids)==1 and counter == (len(self.ids) - self.f):
                            current_dict['GO'] = True
                            current_dict['MSG'] = current_msg
                            return current_dict

                    checked_msgs.append(current_msg)
        return current_dict

    def deliver(self, message):
        # delivering the final message
        print("-----MESSAGE DELIVERED:", message, "-----")
        self.delivered = True
