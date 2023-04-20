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
BREAK_TIME = 0.1

BROADCASTER_ID = 1

class Process:
    def __init__(self):
        self.ids = []
        self.ips = []
        self.selfip = 0
        self.selfid = 0
        self.AL = []
        self.h = 0   # sequence number of the message
        self.delivered = False
        self.start = False
        self.ENC_INF = {}
        self.HASH = {}
        self.MSGSET = {}
        self.COUNTER = {}
        self.CODESET = {}
        # self.SENTMSG = {}   # Variabile non richiesta
        self.RECEIVEDMSG = {}
        self.SENTECHO = {}
        self.RECEIVEDECHO = {}
        self.SENTACC = {}
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
    def __hash(self, message):
        return hashlib.sha256(bytes(message, "utf-8")).hexdigest()
    
    def broadcast(self, message):
        self.__update()   # updating current view of the active processes
        self.faulty = math.floor((len(self.ids) - 1) / 3)   # f<N/3 condition to protocol correctness

        if not self.start:
            self.start = True
            # self.h = self.h+1 # incrementing sequence number
            self.h = self.selfid
            self.encrypt(message, self.selfid, self.h)   # creating coded elements
            message_to_send = {'FLAG': 'MSG', 'FROM': str(self.selfid),
                               'S': str(self.selfid), 'HASH': self.HASH[str(message)],
                               'C': self.CODESET[str(s) + str(self.HASH[str(message)]) + str(self.h)][i],
                               'H': self.h}

            for i in range(len(self.ids)):
                self.AL[i].send(message_to_send)

                # if 'MSG'+str(message['S'])+str(h) not in self.SENTMSG.keys():   # Queste linee di codice non dovrebbero
                #     self.SENTMSG['MSG'+str(message['S'])+str(h)] = []           # essere richieste dall'algoritmo
                # self.SENTMSG['MSG'+str(message['S'])+str(h)].append(str(i+1))   # lui considera solo i msg ricevuti
            self.barrier.wait()

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

    def encrypt(self, msg, s, h):
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
        self.ENC_INF[str(s) + str(hash_msg) + str(h)] = [cipher.nonce, tag, ct]

        emsg = b64encode(cipher.nonce + tag + ct)
        logging.info("PROCESS:%s", emsg)

        if str(s) + str(hash_msg) + str(h) not in self.CODESET[str(s) + str(hash_msg) + str(h)].keys():
            self.CODESET[str(s) + str(hash_msg) + str(h)] = []
        for i in range(0, len(self.ids)):
            self.CODESET[str(s) + str(hash_msg) + str(h)].append(shares[i])
        
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
        except ValueError:
            print("The shares were incorrect")

        return result

    def deliver_msg(self, msg):
        # MESSAGE{'FLAG':flag,'FROM':from,'S':s}
        # id == 1 checks that the delivery is computed with the sender s that by convention it's the first
        # s is meant for the broadcaster or for the source of the message it changes something?
        if msg['FROM'] == msg['S'] and str(msg['FLAG']) == 'MSG' and str(msg['FLAG']) + str(msg['S']) + str(msg['H']) not in self.RECEIVEDMSG.keys():
            self.RECEIVEDMSG[str(msg['FLAG']) + str(msg['S']) + str(msg['H'])] = []
            self.RECEIVEDMSG[str(msg['FLAG']) + str(msg['S']) + str(msg['H'])].append(msg['FROM'])

            if self.selfid == BROADCASTER_ID:
                self.barrier.wait()
            else:
                self.__update()  # If writer_id == 1 then it is correct, otherwise no
                self.faulty = math.floor((len(self.ids) - 1) / 3)  # f<N/3 condition to protocol correctness

            logging.info(
                "PROCESS: %d,%s --- Starting the ECHO part...", self.selfid, self.selfip
            )

            if str(msg['S']) + str(msg['HASH']) + str(msg['H']) not in self.CODESET.keys():
                self.CODESET[str(msg['S']) + str(msg['HASH']) + str(msg['H'])] = []
            self.CODESET[str(msg['S']) + str(msg['HASH']) + str(msg['H'])].append(msg['C'])

            # TODO Linea commentata perchè non dovrebbe funzionare
            # self.COUNTER[str('ECHO') + str(msg['S']) + str(msg['HASH']) + str(msg['H'])] = self.COUNTER[str('ECHO') + str(msg['S']) + str(msg['HASH']) + str(msg['H'])]+1

            if str('ECHO') + str(msg['S']) + str(msg['H']) not in self.SENTECHO.keys():
                self.SENTECHO[str('ECHO') + str(msg['S']) + str(msg['H'])] = []
                
                msg_temp = {'FLAG': 'ECHO', 'FROM': str(self.selfid), 'S': str(msg['S']), 'H': str(msg['H']),
                            'HASH': str(msg['HASH']), 'C': msg['C']}

                for i in range(len(self.ids)):
                    # TODO controllare perché la send dovrebbe essere invocata con un solo parametro
                    self.AL[i].send('ECHO', msg_temp, msg['HASH'], msg['C'], msg['H'])
                    # TODO controllare perché la sentecho dovrebbe contenere un solo unico messaggio
                    # TODO che simboleggia la send in generale
                    self.SENTECHO['ECHO' + str(msg['S']) + str(msg['H'])].append(str(i + 1))
                self.barrier.wait()

    def get_powerset(some_list):
    
        if len(some_list) == 0:
            return [[]]

        subsets = []
        first_element = some_list[0]
        remaining_list = some_list[1:]
        # Strategy: get all the subsets of remaining_list. For each
        # of those subsets, a full subset list will contain both
        # the original subset as well as a version of the subset
        # that contains first_element
        for partial_subset in get_powerset(remaining_list):
            subsets.append(partial_subset)
            subsets.append(partial_subset[:] + [first_element])

        return subsets

    def deliver_echo(self, msg):   # TODO flag,source may be in the input of these functions

        # TODO Questa linea potrebbe essere eliminata perché il livello sottostante passa solo messaggi ECHO
        # if str(msg['FLAG']) == 'ECHO':
    
            if str(msg['FLAG']) + str(msg['S']) + str(msg['H']) not in self.RECEIVEDECHO.keys():
                self.RECEIVEDECHO[str(msg['FLAG']) + str(msg['S']) + str(msg['H'])] = []

            if msg['FROM'] not in self.RECEIVEDECHO[str(msg['FLAG']) + str(msg['S']) + str(msg['H'])].values():
                self.RECEIVEDECHO[str(msg['FLAG']) + str(msg['S']) + str(msg['H'])].append(msg['FROM'])
                self.COUNTER[str(msg['FLAG']) + str(msg['S']) + str(msg['HASH']) + str(msg['H'])] = self.COUNTER[str(msg['FLAG'])+str(msg['S'])+str(msg['HASH'])+ str(msg['H'])]+1

                if str(msg['S']) + str(msg['HASH']) + str(msg['H']) not in self.CODESET.keys():
                    self.CODESET[str(msg['S']) + str(msg['HASH'])+str(msg['H'])] = []
                self.CODESET[str(msg['FLAG']) + str(msg['S']) + str(msg['HASH']) + str(msg['H'])].append(msg['C'])

                if self.COUNTER[str(msg['FLAG']) + str(msg['S']) + str(msg['HASH']) + str(msg['H'])] >= self.faulty+1:
                    b = False
                    if str(msg['S']) + str(msg['H']) not in self.MSGSET.keys():
                        self.MSGSET[str(msg['S']) + str(msg['H'])] = []
                    for j in self.MSGSET[str(msg['S']) + str(msg['H'])]:
                        if j[0] == str(msg['HASH']):
                            b = True
                            break
                    if not b:
                        # checking condition and why j
                        if str(msg['S'])+str(msg['HASH'])+str(msg['FROM']) not in self.CODESET.keys():
                            self.CODESET[str(msg['S'])+str(msg['HASH'])+str(msg['FROM'])] = []
                        
                        C = []
                        C = self.CODESET[str(msg['S'])+str(msg['HASH'])+str(msg['FROM'])]
                        C = self.get_powerset(C)
                        
                        for l in C:
                            if len(l) == self.faulty+1:
                                m = self.decrypt(l, msg['S'], msg['H'], msg['HASH'])   # TODO checking if passing a set coherent with decrypt function
                                hash_msg = self.__hash(m)
                                self.HASH[str(m)] = hash_msg
                                if msg['HASH'] == hash_msg:
                                    self.MSGSET[str(msg['S']) + str(msg['H'])].append((msg['HASH'], m))
                self.check(msg['S'], msg['HASH'], msg['H'])
                    
    def deliver_acc(self, msg):
        if str(msg['FLAG']) == 'ACC':
            if str(msg['FLAG']) + str(msg['S']) + str(msg['H']) not in self.RECEIVEDACC.keys():
                self.RECEIVEDACC[str(msg['FLAG']) + str(msg['S']) + str(msg['H'])] = []
            if msg['FROM'] not in self.RECEIVEDACC[str(msg['FLAG']) + str(msg['S']) + str(msg['H'])].values():
                self.RECEIVEDACC[str(msg['FLAG']) + str(msg['S']) + str(msg['H'])].append(msg['FROM'])
                self.COUNTER[str(msg['FLAG']) + str(msg['S']) + str(msg['HASH']) + str(msg['H'])] = self.COUNTER[str(msg['FLAG'])+str(msg['S'])+str(msg['HASH'])+str(msg['H'])]+1
                if self.COUNTER[str(msg['FLAG'])+str(msg['S'])+str(msg['HASH'])+str(msg['H'])] >= self.faulty + 1:
                    b = False
                    if str(msg['S']) + str(msg['H']) not in self.MSGSET.keys():
                        self.MSGSET[str(msg['S']) + str(msg['H'])] = []
                    for j in self.MSGSET[str(msg['S']) + str(msg['H'])]:
                        if j[0] == str(msg['HASH']):
                            b = True
                            break
                    if not b:
                        msg_temp = {}
                        msg_temp['FLAG'] = 'REQ'
                        # self.broadcast(msg_temp, s, H, h)
                        # self.h = self.h+1   # incrementing sequence number
                        msg_temp['FROM'] = str(self.selfid)
                        msg_temp['S'] = str(msg['S'])
                        for j in range(0, len(self.ids)):
                            if str('REQ') + str(msg['S']) + str(msg['HASH']) + str(msg['H']) not in self.SENTREQ.keys():
                                self.SENTREQ[str('REQ')+str(msg['S'])+str(msg['HASH']) + str(msg['H'])] = []
                            if str(j) not in self.SENTREQ[str('REQ') + str(msg['S']) + str(msg['HASH']) + str(msg['H'])].values():
                                self.AL[j].send(msg_temp, msg['HASH'], msg['H'])   # source already in message
                                self.SENTREQ['REQ' + str(msg['S']) + str(msg['HASH']) + str(msg['H'])].append(str(j + 1))
                self.check(msg['FROM'], msg['HASH'], msg['H'])

    def deliver_req(self, msg):
        if str(msg['FLAG']) == 'REQ':
            if str(msg['FLAG']) + str(msg['S']) + str(msg['H']) not in self.RECEIVEDREQ.keys():
                self.RECEIVEDREQ[str(msg['FLAG']) + str(msg['S']) + str(msg['H'])] = []
            if msg['FROM'] not in self.RECEIVEDREQ[str(msg['FLAG']) + str(msg['S']) + str(msg['H'])].values():
                self.RECEIVEDREQ[str(msg['FLAG']) + str(msg['S']) + str(msg['H'])].append(msg['FROM'])
                b = False
                m = 0
                if str(msg['S']) + str(msg['H']) not in self.MSGSET.keys():
                    self.MSGSET[str(msg['S']) + str(msg['H'])] = []
                for j in self.MSGSET[str(msg['S']) + str(msg['H'])]:
                    if j[0] == str(msg['HASH']):
                        b = True
                        m = j[1]
                        break
                if b:
                    msg_temp = {'FLAG': 'FWD', 'FROM': str(self.selfid), 'S': str(msg['S']), 'HASH': msg['HASH'],
                                'H': msg['H']}
                    self.AL[int(msg['FROM'])-1].send(msg_temp)

                    if str('FWD') + str(msg['S']) + str(msg['HASH']) + str(msg['H']) not in self.SENTFWD.keys():
                        self.SENTFWD[str('REQ') + str(msg['S']) + str(msg['HASH']) + str(msg['H'])] = []
                    self.SENTFWD['REQ' + str(message['S']) + str(msg['HASH']) + str(msg['H'])].append(str(msg['FROM']))

    def deliver_fwd(self, msg):
        if str(msg['FLAG']) + str(msg['S']) + str(msg['HASH']) + str(msg['H']) not in self.SENTREQ.keys():
            self.SENTREQ[str(msg['FLAG']) + str(msg['S']) + str(msg['HASH']) + str(msg['H'])] = []
        if msg['FROM'] in self.SENTREQ[str(msg['FLAG']) + str(msg['S']) + str(msg['HASH']) + str(msg['H'])].values():
            if str(msg['FLAG']) + str(msg['S']) + str(msg['MSG']) + str(msg['H']) not in self.RECEIVEDFWD.keys():
                self.RECEIVEDFWD[str(msg['FLAG']) + str(msg['S']) + str(msg['MSG']) + str(msg['H'])] = []
            if msg['FROM'] not in self.RECEIVEDFWD[str(msg['FLAG']) + str(msg['S']) + str(msg['MSG']) + str(msg['H'])].values():
                self.RECEIVEDFWD[str(msg['FLAG']) + str(msg['S']) + str(msg['MSG']) + str(msg['H'])].append(str(msg['FROM']))
                self.MSGSET[str(msg['S']) + str(msg['H'])].append((msg['HASH'], msg['MSG']))
                hash_msg = self.__hash(msg['MSG'])
                self.HASH[str(msg['MSG'])] = hash_msg
                self.check(msg['S'], hash_msg, msg['H'])

    def check(self, s, H, h):
        b = False
        if str(s) + str(h) not in self.MSGSET.keys():
            self.MSGSET[str(s) + str(h)] = []
        for j in self.MSGSET[str(s) + str(h)]:
            if j[0] == str(H):
                b = True
                m = j[1]
                break
        if b:
            if self.COUNTER[str('ECHO')+str(s)+str(H)+str(h)] >= self.faulty+1:
                if str('ECHO')+str(s)+str(h) not in self.SENTECHO.keys():
                    self.SENTECHO[str('ECHO')+str(s)+str(h)] = []
                
                    msg_temp = {}
                    msg_temp['FLAG'] = 'ECHO'
                    # self.broadcast(msg_temp, s, H, c,h)
                    # self.h=self.h+1 # incrementing sequence number
                    msg_temp['FROM'] = str(self.selfid)
                    msg_temp['S'] = str(s)

                    for i in range(len(self.ids)):
                        self.AL[i].send('ECHO', msg_temp, H, self.CODESET[str(s) + str(H) + str(h)][self.selfid], h)
                        self.SENTECHO['ECHO' + str(msg['S']) + str(h)].append(str(i + 1))
                    self.barrier.wait()

            if self.COUNTER[str('ECHO') + str(s) + str(H) + str(h)] >= len(self.ids)-self.faulty:
                if str('ACC') + str(s) + str(h) not in self.SENTACC.keys():
                    self.SENTACC[str('ACC') + str(s) + str(h)] = []
                    msg_temp = {}
                    msg_temp['FLAG'] = 'ACC'
                    # self.broadcast(msg_temp, s, H, c,h)
                    # self.h=self.h+1 # incrementing sequence number
                    msg_temp['FROM'] = str(self.selfid)
                    msg_temp['S'] = str(s)

                    # self.broadcast(msg,s,H,h)
                    for i in range(len(self.ids)):
                        self.AL[i].send('ACC', msg_temp, H, h)
                        self.SENTACC['ACC' + str(s) + str(h)].append(str(i+1))
                    self.barrier.wait()

            if self.COUNTER[str('ACC') + str(s) + str(H) + str(h)] >= self.faulty+1:
                if str('ACC') + str(s) + str(h) not in self.SENTACC.keys():
                    self.SENTACC[str('ACC') + str(s) + str(h)] = []
                    msg_temp = {}
                    msg_temp['FLAG'] = 'ACC'
                    # self.broadcast(msg_temp, s, H, c,h)
                    # self.h=self.h+1 # incrementing sequence number
                    msg_temp['FROM'] = str(self.selfid)
                    msg_temp['S'] = str(s)
                    for i in range(len(self.ids)):
                        self.AL[i].send('ACC', msg_temp, H, h)
                        self.SENTACC['ACC'+str(s)+str(h)].append(str(i+1))
                    self.barrier.wait()
            if self.COUNTER[str('ACC')+str(s)+str(H)+str(h)] >= len(self.ids)-self.faulty:
                msg = {}
                msg['S'] = s
                msg['H'] = h
                self.deliver(msg)
                for i in range(0, len(self.ids)):
                    self.AL[i].terminating_flag = True  # TODO check if I can close all the link now
                                
    def deliver(self, msg):
        # delivering the final message that is a dictionary
        print("-----MESSAGE DELIVERED:", self.MSGSET[str(msg['S']) + str(msg['H'])][1])
        delivered = True
