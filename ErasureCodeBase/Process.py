import math
import hashlib
import pika as pika
import AuthenticatedLink
import socket
import threading
import json
import struct
import logging
from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from binascii import unhexlify
from base64 import b64decode, b64encode

SERVER_ID = "192.168.1.40"
SERVER_PORT = 5000

RCV_BUFFER_SIZE = 1024

BROADCASTER_ID = 1


# TODO check if self.HASH is useful
class Process:
    def __init__(self):
        self.ids = []
        self.ips = []
        self.selfip = 0
        self.selfid = 0
        self.AL = []
        self.h = 0   # sequence number of the message
        self.start = False
        self.ENC_INF = {}
        self.HASH = {}
        self.MsgSet = {}
        self.COUNTER = {}
        self.CodeSet = {}
        # self.SENTMSG = {}   # Variabile non richiesta
        self.ReceivedMsg = []   # List instead of dictionary
        self.SentECHO = []   # List instead of dictionary
        self.RECEIVEDECHO = {}
        self.SentACC = []   # List instead of dictionary
        self.RECEIVEDACC = {}
        self.SENTREQ = {}
        self.RECEIVEDREQ = {}
        self.RECEIVEDFWD = {}
        self.faulty = 0

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
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)
        self.selfip = IPAddr
        self.selfid = self.ids[self.ips.index(self.selfip)]
        self.barrier = threading.Barrier(parties=2)
        for i in range(0, len(self.ids)):
            self.AL.append(
                AuthenticatedLink.AuthenticatedLink(
                    self.selfid, self.selfip, self.ids[i], self.ips[i], self
                )
            )
            self.AL[i].receiver()

    def __update(self):
        with pika.BlockingConnection(
            pika.ConnectionParameters(host=SERVER_ID)
        ) as connection:
            channel = connection.channel()

            response = channel.queue_declare(queue=str(self.selfid))
            # Get the queue length (number of not consumed messages)
            num = response.method.message_count

            logging.info(
                "PROCESS: %d,%s --- My queue length: %d", self.selfid, self.selfip, num
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
                    self.ips.append(ip_from_queue)
                    self.ids.append(int(id_from_queue))
                    self.AL.append(
                        AuthenticatedLink.AuthenticatedLink(
                            self.selfid,
                            self.selfip,
                            self.ids[len(self.ids) - 1],
                            self.ips[len(self.ips) - 1],
                            self,
                        )
                    )
                    self.AL[len(self.AL) - 1].receiver()
                self.counter += 1
                if self.counter == num:
                    channel.stop_consuming()
                    channel.close()

            channel.basic_consume(
                queue=str(self.selfid), on_message_callback=callback, auto_ack=True
            )
            channel.start_consuming()

    # message must be a string
    @staticmethod
    def __hash(message):
        return hashlib.sha256(bytes(message, "utf-8")).hexdigest()

    def process_receive(self, message):
        # receive messages from the underlying link
        match message.get('FLAG'):
            case "MSG":
                self.deliver_msg(message)

            case "ECHO":
                self.deliver_echo(message)

            case "ACC":
                self.deliver_acc(message)

            case "REQ":
                self.deliver_req(message)

            case "FWD":
                self.deliver_fwd(message)

            case _:
                logging.info("PROCESS:ERROR:Received a message of flag undefined")

    def encrypt(self, msg, sid, sn):
        # Compute the hash of the message
        hash_msg = self.__hash(msg)
        self.HASH[str(msg)] = hash_msg

        # Preparation of the Shamir algorithm
        key = get_random_bytes(16)
        shares = Shamir.split(self.faulty + 1, len(self.ips), key)
        for idx, share in shares:
            logging.info("PROCESS:Index #%d: %s" % (idx, hexlify(share)))

        # Creation of the n fragments
        cipher = AES.new(key, AES.MODE_EAX)
        ct, tag = cipher.encrypt(msg.encode()), cipher.digest()

        # TODO hash_msg dovrebbe essere l'hash del messaggio (prima c'era una H che non era collegata a nulla)
        self.ENC_INF[str(sid) + str(hash_msg) + str(sn)] = [cipher.nonce, tag, ct]

        emsg = b64encode(cipher.nonce + tag + ct)
        logging.info("PROCESS:%s", emsg)

        if str(sid) + str(hash_msg) + str(sn) not in self.CodeSet[str(sid) + str(hash_msg) + str(sn)].keys():
            self.CodeSet[str(sid) + str(hash_msg) + str(sn)] = []
        for i in range(0, len(self.ids)):
            self.CodeSet[str(sid) + str(hash_msg) + str(sn)].append(shares[i])
        
    def decrypt(self, C, s, h, H):
        # create a 4 data block with 2 parity block code generator

        # C must be a list of tuples like (index,share)

        key = Shamir.combine(C)

        nonce, tag = self.ENC_INF[str(s) + str(H) + str(h)][:2]
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        try:
            result = cipher.decrypt(self.ENC_INF[str(s) + str(H) + str(h)][2])
            cipher.verify(tag)
            logging.info("Result of decryption:%s", result)
            return result
        except ValueError:
            print("The shares were incorrect")

    # The function returns all the subsets of the list passed as a parameter
    # [1, 2, 3] -> [[1], [2], [3], [1, 2], [1, 3], [1, 2, 3]]
    def get_powerset(self, some_list):

        if len(some_list) == 0:
            return [[]]

        subsets = []
        first_element = some_list[0]
        remaining_list = some_list[1:]
        # Strategy: get all the subsets of remaining_list. For each
        # of those subsets, a full subset list will contain both
        # the original subset as well as a version of the subset
        # that contains first_element
        for partial_subset in self.get_powerset(remaining_list):
            subsets.append(partial_subset)
            subsets.append(partial_subset[:] + [first_element])

        return subsets

    def broadcast(self, message):
        self.__update()   # updating current view of the active processes
        self.faulty = math.floor((len(self.ids) - 1) / 3)   # f < N/3 condition to protocol correctness

        if not self.start:
            self.start = True
            # self.h = self.h+1 # incrementing sequence number
            self.h = self.selfid
            self.encrypt(message, self.selfid, self.h)   # creating coded elements and inserting them into self.CodeSet

            for i in range(len(self.ids)):
                message_to_send = {'FLAG': 'MSG', 'FROM': str(self.selfid), 'SOURCE': str(self.selfid), 'HASH': self.HASH[str(message)],
                                   'C': self.CodeSet[str(self.selfid) + str(self.HASH[str(message)]) + str(self.h)][i], 'SEQUENCENUMBER': self.h}
                self.AL[i].send(message_to_send)

                # if 'MSG'+str(message['S'])+str(h) not in self.SENTMSG.keys():   # Queste linee di codice non dovrebbero
                #     self.SENTMSG['MSG'+str(message['S'])+str(h)] = []           # essere richieste dall'algoritmo
                # self.SENTMSG['MSG'+str(message['S'])+str(h)].append(str(i+1))   # lui considera solo i msg ricevuti
            self.barrier.wait()

    def deliver_msg(self, msg):
        # MESSAGE{'FLAG':flag,'FROM':from,'S':s}
        # id == 1 checks that the delivery is computed with the sender s that by convention it's the first
        # s is meant for the broadcaster or for the source of the message it changes something?
        if msg['FROM'] == msg['SOURCE'] and ['MSG', str(msg['SOURCE']), str(msg['SEQUENCENUMBER'])] not in self.ReceivedMsg:
            self.ReceivedMsg.append(['MSG', str(msg['SOURCE']), str(msg['SEQUENCENUMBER'])])

            if self.selfid == BROADCASTER_ID:
                self.barrier.wait()
            else:
                self.__update()  # If writer_id == 1 then it is correct, otherwise no
                self.faulty = math.floor((len(self.ids) - 1) / 3)  # f<N/3 condition to protocol correctness

            logging.info(
                "PROCESS: %d,%s --- Starting the ECHO part...", self.selfid, self.selfip
            )

            if str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER']) not in self.CodeSet.keys():
                self.CodeSet[str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])] = []
            self.CodeSet[str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])].append(msg['C'])

            # TODO Linea commentata perchè non dovrebbe funzionare
            # self.COUNTER[str('ECHO') + str(msg['S']) + str(msg['HASH']) + str(msg['H'])] = self.COUNTER[str('ECHO') + str(msg['S']) + str(msg['HASH']) + str(msg['H'])]+1

            if ['ECHO', msg['SOURCE'], msg['SEQUENCENUMBER']] not in self.SentECHO:
                self.SentECHO.append(['ECHO', msg['FROM'], msg['SEQUENCENUMBER']])
                
                packet = {'FLAG': 'ECHO', 'FROM': str(self.selfid), 'SOURCE': str(msg['SOURCE']),
                          'HASH': str(msg['HASH']), 'C': str(msg['C']), 'SEQUENCENUMBER': str(msg['SEQUENCENUMBER'])}

                for i in range(len(self.ids)):
                    self.AL[i].send(packet)
                self.barrier.wait()

    def deliver_echo(self, msg):
        # used not to generate the error
        if str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['SEQUENCENUMBER']) not in self.RECEIVEDECHO.keys():
            self.RECEIVEDECHO[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])] = []

        if msg['FROM'] not in self.RECEIVEDECHO[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])].values():
            self.RECEIVEDECHO[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])].append(msg['FROM'])
            self.COUNTER[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])] += 1

            # used not to generate the error
            if str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER']) not in self.CodeSet.keys():
                self.CodeSet[str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])] = []
            self.CodeSet[str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])].append(msg['C'])

            if self.COUNTER[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])] >= self.faulty + 1:
                there_is = False
                if str(msg['SOURCE']) + str(msg['SEQUENCENUMBER']) not in self.MsgSet.keys():
                    self.MsgSet[str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])] = []
                for j in self.MsgSet[str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])]:
                    if self.__hash(j) == str(msg['HASH']):
                        there_is = True
                        break
                if not there_is:
                    # checking condition and why j
                    if str(msg['SOURCE']) + str(msg['HASH']) + str(msg['FROM']) not in self.CodeSet.keys():
                        self.CodeSet[str(msg['SOURCE']) + str(msg['HASH']) + str(msg['FROM'])] = []

                    subset = self.CodeSet[str(msg['SOURCE']) + str(msg['HASH']) + str(msg['FROM'])]
                    c = self.get_powerset(subset)
                        
                    for l in c:
                        if len(l) == self.faulty + 1:
                            m = self.decrypt(l, msg['SOURCE'], msg['SEQUENCENUMBER'], msg['HASH'])   # TODO checking if passing a set coherent with decrypt function
                            hash_msg = self.__hash(m)
                            self.HASH[str(m)] = hash_msg
                            if msg['HASH'] == hash_msg:
                                self.MsgSet[str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])].append(m)

            self.check(msg['SOURCE'], msg['HASH'], msg['SEQUENCENUMBER'])
                    
    def deliver_acc(self, msg):
        if str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['SEQUENCENUMBER']) not in self.RECEIVEDACC.keys():
            self.RECEIVEDACC[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])] = []

        if msg['FROM'] not in self.RECEIVEDACC[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])].values():
            self.RECEIVEDACC[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])].append(msg['FROM'])
            self.COUNTER[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])] += 1

            if self.COUNTER[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])] >= self.faulty + 1:
                there_is = False
                if str(msg['SOURCE']) + str(msg['SEQUENCENUMBER']) not in self.MsgSet.keys():
                    self.MsgSet[str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])] = []
                for j in self.MsgSet[str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])]:
                    if self.__hash(j) == str(msg['HASH']):
                        there_is = True
                        break
                if not there_is:
                    packet = {'FLAG': 'REQ', 'SOURCE': str(msg['SOURCE']), 'FROM': str(self.selfid),
                              'HASH': str(msg['HASH']), 'SEQUENCENUMBER': str(msg['SEQUENCENUMBER'])}
                    for j in range(0, len(self.ids)):
                        if 'REQ' + str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER']) not in self.SENTREQ.keys():
                            self.SENTREQ['REQ' + str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])] = []
                        if str(j + 1) not in self.SENTREQ['REQ' + str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])].values():
                            # j + 1 is used both above and below because it is the real id of another process
                            self.SENTREQ[
                                'REQ' + str(msg['SOURCE']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])].append(
                                str(j + 1))
                            self.AL[j].send(packet)

            # TODO Questa riga dovrebbe essere sbagliata proprio nell'algoritmo
            self.check(msg['FROM'], msg['HASH'], msg['SEQUENCENUMBER'])

    def deliver_req(self, msg):
        if str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['SEQUENCENUMBER']) not in self.RECEIVEDREQ.keys():
            self.RECEIVEDREQ[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])] = []
        if msg['FROM'] not in self.RECEIVEDREQ[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])].values():
            self.RECEIVEDREQ[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])].append(msg['FROM'])
            there_is = False
            message = ""
            if str(msg['SOURCE']) + str(msg['SEQUENCENUMBER']) not in self.MsgSet.keys():
                self.MsgSet[str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])] = []
            for j in self.MsgSet[str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])]:
                if self.__hash(j) == str(msg['HASH']):
                    there_is = True
                    message = j
                    break
            if there_is:
                packet = {'FLAG': 'FWD', 'FROM': str(self.selfid), 'SOURCE': str(msg['SOURCE']), 'MESSAGE': message,
                          'SEQUENCENUMBER': msg['SEQUENCENUMBER']}
                self.AL[int(msg['FROM']) - 1].send(packet)

                # TODO Non so se questa parte sia utile
                # if str('FWD') + str(msg['S']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER']) not in self.SENTFWD.keys():
                #    self.SENTFWD[str('REQ') + str(msg['S']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])] = []
                # self.SENTFWD['REQ' + str(message['S']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])].append(str(msg['FROM']))

    def deliver_fwd(self, msg):
        hash_msg = self.__hash(msg['MESSAGE'])
        if str(msg['FLAG']) + str(msg['SOURCE']) + str(hash_msg) + str(msg['SEQUENCENUMBER']) not in self.SENTREQ.keys():
            self.SENTREQ[str(msg['FLAG']) + str(msg['SOURCE']) + str(hash_msg) + str(msg['SEQUENCENUMBER'])] = []
        # msg['FROM'] is the real id of the process
        if msg['FROM'] in self.SENTREQ[str(msg['FLAG']) + str(msg['SOURCE']) + str(hash_msg) + str(msg['SEQUENCENUMBER'])].values():
            if str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['MESSAGE']) + str(msg['SEQUENCENUMBER']) not in self.RECEIVEDFWD.keys():
                self.RECEIVEDFWD[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['MESSAGE']) + str(msg['SEQUENCENUMBER'])] = []
            if msg['FROM'] not in self.RECEIVEDFWD[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['MESSAGE']) + str(msg['SEQUENCENUMBER'])].values():
                self.RECEIVEDFWD[str(msg['FLAG']) + str(msg['SOURCE']) + str(msg['MESSAGE']) + str(msg['SEQUENCENUMBER'])].append(str(msg['FROM']))
                self.MsgSet[str(msg['SOURCE']) + str(msg['SEQUENCENUMBER'])].append(msg['MESSAGE'])
                self.HASH[str(msg['MESSAGE'])] = hash_msg
                self.check(msg['SOURCE'], hash_msg, msg['SEQUENCENUMBER'])

    def check(self, s, hash_msg, sn):
        there_is = False
        message = ""
        if str(s) + str(sn) not in self.MsgSet.keys():
            self.MsgSet[str(s) + str(sn)] = []
        for j in self.MsgSet[str(s) + str(sn)]:
            if self.__hash(j) == str(hash_msg):
                there_is = True
                message = j
                break
        if there_is:

            if self.COUNTER['ECHO' + str(s) + str(hash_msg) + str(sn)] >= self.faulty + 1:
                if ['ECHO', str(s), str(sn)] not in self.SentECHO:
                    self.SentECHO.append(['ECHO', s, sn])
                    for i in range(len(self.ids)):
                        packet = {'FLAG': 'ECHO', 'FROM': str(self.selfid), 'SOURCE': str(s), 'HASH': str(hash_msg),
                                  'C': self.CodeSet[str(s) + str(hash_msg) + str(sn)][self.selfid],
                                  'SEQUENCENUMBER': str(sn)}
                        self.AL[i].send(packet)

            elif self.COUNTER['ECHO' + str(s) + str(hash_msg) + str(sn)] >= len(self.ids) - self.faulty:
                if ['ACC', str(s), str(sn)] not in self.SentACC:
                    self.SentACC.append(['ACC', s, sn])

                    for i in range(len(self.ids)):
                        packet = {'FLAG': 'ACC', 'FROM': str(self.selfid), 'SOURCE': str(s), 'HASH': hash_msg,
                                  'SEQUENCENUMBER': str(sn)}
                        self.AL[i].send(packet)

            elif self.COUNTER['ACC' + str(s) + str(hash_msg) + str(sn)] >= self.faulty + 1:
                if ['ACC', str(s), str(sn)] not in self.SentACC:
                    self.SentACC.append(['ACC', s, sn])

                    for i in range(len(self.ids)):
                        packet = {'FLAG': 'ACC', 'FROM': str(self.selfid), 'SOURCE': str(s), 'HASH': hash_msg,
                                  'SEQUENCENUMBER': str(sn)}
                        self.AL[i].send(packet)

            elif self.COUNTER['ACC' + str(s) + str(hash_msg) + str(sn)] >= len(self.ids) - self.faulty:
                msg = {'SOURCE': s, 'MESSAGE': message, 'SEQUENCENUMBER': sn}
                self.__deliver(msg)

    @staticmethod
    def __deliver(msg):
        # delivering the final message that is a dictionary
        print("-----MESSAGE DELIVERED: ", msg)
