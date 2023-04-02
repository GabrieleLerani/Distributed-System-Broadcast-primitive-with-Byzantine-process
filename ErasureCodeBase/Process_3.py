import math
import hashlib
import pika as pika
import AuthenticatedLink
import socket
import threading
from threading import Thread
import time
import json
import struct
import logging
import rs

SERVER_ID = "192.168.1.40"
SERVER_PORT = 5000

RCV_BUFFER_SIZE = 1024
BREAK_TIME = 0.1

BROADCASTER_ID=1

N=10
K=5

KEY=""


class Process:
    def __init__(self):
        self.ids = []
        self.ips = []
        self.sip = 0
        self.sid = 0
        self.AL = []
        self.h=0 # sequence number of the message
        self.delivered = False
        self.start=False
        self.HASH={}
        self.MSGSET = {}
        self.COUNTER={}
        self.CODESET = {}
        self.SENTMSG={}
        self.RECEIVEDMSG={}
        self.SENTECHO={}
        self.RECEIVEDECHO={}
        self.SENTACC={}
        self.RECEIVEDACC={}
        self.SENTREQ={}
        self.RECEIVEDREQ={}
        self.RECEIVEDFWD={}
        self.faulty = math.floor(len(self.ids) / 3) # f<N/3 condition to protocol correctness

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
    
    def broadcast(self, message,s=self.sid,H='#',c='#',h=self.h): 
        self.__update() # updating current view of the active processes 

        if not self.start:
            msg_temp=message
            message['FLAG']='MSG'

        match message['FLAG']:

            case 'MSG':
                if not self.start:
                    self.start=True
                    #self.h=self.h+1 # incrementing sequence number
                    self.h=self.sid
                    h=self.h
                message['FROM']=str(self.sid)
                message['S']=str(self.sid)
                self.encrypt(msg_temp, self.sid, self.h) # creating coded elements
                for i in range(len(self.ids)):
                    self.AL[i].send(message,self.HASH[str(msg_temp)],self.CODESET[str(s)+str(self.HASH[str(msg_temp)])+str(h)][i],h)
                    if 'MSG'+str(message['S'])+str(h) not in self.SENTMSG.keys():
                        self.SENTMSG['MSG'+str(message['S'])+str(h)]=[]
                    self.SENTMSG['MSG'+str(message['S'])+str(h)].append(str(i+1))
                self.barrier.wait()
            case 'ECHO':
                #self.h=self.h+1 # incrementing sequence number
                self.h=self.sid
                message['FROM']=str(self.sid)
                message['S']=str(s)
                for i in range(len(self.ids)):
                    self.AL[i].send(message,H,c,h)
                    if 'ECHO'+str(message['S'])+str(h) not in self.SENTECHO.keys():
                        self.SENTECHO['ECHO'+str(message['S'])+str(h)]=[]
                    self.SENTECHO['ECHO'+str(message['S'])+str(h)].append(str(i+1))
                self.barrier.wait()
            case 'REQ':
                # self.h=self.h+1 # incrementing sequence number
                self.h=self.sid
                message['FROM']=str(self.sid)
                message['S']=str(s)
                for j in range(0,len(self.ids)):
                    if str('REQ')+str(s)+str(H)+str(h) not in self.SENTREQ.keys():
                        self.SENTREQ[str('REQ')+str(s)+str(H)+str(h)]=[]
                    if str(j) not in self.SENTREQ[str('REQ')+str(s)+str(H)+str(h)].values():
                        self.AL[j].send(message,H,h)
                        self.SENTREQ['REQ'+str(message['S'])+str(H)+str(h)].append(str(j+1))     
            case _:
                logging.info("PROCESS:ERROR: impossible to send a message with flag unknown")

    def encrypt(self,msg,s,h):
        
        # create a 4 data block with 2 parity block code generator
        generator = rs.RSCoder(N, K)

        # encode data
        encoded_data = generator.encode(msg)

        H=hmac.new( KEY, msg, hashlib.sha256 ).hexdigest()
        self.HASH[str(msg)]=str(H)
        if str(s)+str(H)+str(h) not in self.CODESET[str(s)+str(H)+str(h)].keys():
           self.CODESET[str(s)+str(H)+str(h)]=[]
        for i in range(0,len(encoded_data)):
            self.CODESET[str(s)+str(H)+str(h)].append(encoded_data[i])
        
    def decrypt(self,C):
        # create a 4 data block with 2 parity block code generator
        generator = rs.RSCoder(N, K)

        # regenerate lost data
        regenerated_data = generator.decode(C[0],C[1:])# TODO check if it is correct

        # logging the result
        logging.info("PROCESS:Regenerated data %s",regenerated_data)


        return regenerated_data

    def deliver_msg(self, msg,s,H,c,h):# MESSAGE{'FLAG':flag,'FROM':from,'S':s}
        # id == 1 checks that the delivery is computed with the sender s that by convention it's the first
        if msg['FROM'] == msg['S'] and str(msg['FLAG'])+str(s)+str(h) not in self.RECEIVEDMSG.keys():
            self.RECEIVEDMSG[str(msg['FLAG'])+str(s)+str(h)]=[]
            self.RECEIVEDMSG[str(msg['FLAG'])+str(s)+str(h)].append(msg['FROM'])

            if self.sid == BROADCASTER_ID:
                self.barrier.wait()
            else:
                self.__update()  # If writer_id == 1 then it is correct, otherwise no

            logging.info(
                "PROCESS: %d,%s --- Starting the ECHO part...", self.sid, self.sip
            )
            if str(s)+str(H)+str(h) not in self.CODESET.keys():
                self.CODESET[str(s)+str(H)+str(h)]=[]
            self.CODESET[str(s)+str(H)+str(h)].append(str(c))

            self.COUNTER[str('ECHO')+str(s)+str(H)+ str(h)]=self.COUNTER[str('ECHO')+str(s)+str(H)+ str(h)]+1
            if str('ECHO')+str(s)+str(h) not in self.SENTECHO.keys():
                self.SENTECHO[str('ECHO')+str(s)+str(h)]=[]
                msg_temp={}
                msg_temp['FLAG']='ECHO'
                self.broadcast(msg_temp, s, H, c,h)

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

    def deliver_echo(self, msg ,s,H,c,h):
        if str(msg['FLAG'])+str(s)+str(h) not in self.RECEIVEDECHO.keys():
            self.RECEIVEDECHO[str(msg['FLAG'])+str(s)+str(h)]=[]

        if msg['FROM'] not in self.RECEIVEDECHO[str(msg['FLAG'])+str(s)+str(h)].values():
            self.RECEIVEDECHO[str(msg['FLAG'])+str(s)+str(h)].append(msg['FROM'])
            self.COUNTER[str(msg['FLAG'])+str(s)+str(H)+ str(h)]=self.COUNTER[str(msg['FLAG'])+str(s)+str(H)+ str(h)]+1

            if str(msg['FLAG'])+str(s)+str(h) not in self.CODESET.keys():
                self.CODESET[str(s)+str(H)+str(h)]=[]
            self.CODESET[str(s)+str(H)+str(h)].append(str(c))

            if self.COUNTER[str(msg['FLAG'])+str(s)+str(H)+ str(h)]>=self.faulty+1:
                b=False
                if str(s)+str(h) not in self.MSGSET.keys():
                    self.MSGSET[str(s)+str(h)]=[]
                for j in self.MSGSET[str(s)+str(h)]:
                     if j[0]==str(H):
                        b=True
                        break
                if b==False:
                    # checking condition and why j
                    if str(msg['FLAG'])+str(s)+str(msg['FROM']) not in self.CODESET.keys():
                            self.CODESET[str(s)+str(H)+str(msg['FROM'])]=[]
                    while True:
                        C=[]
                        C=self.CODESET[str(s)+str(H)+str(msg['FROM'])]
                        C=self.get_powerset(C)
                        
                        for l in C:
                        
                            if len(l)==self.faulty+1:
                                m=self.decrypt(l) 
                                
                            if H==hmac.new( KEY, m, hashlib.sha256 ):
                                    self.MSGSET[str(s)+str(h)].append((H,m))
            self.check(s, H, h)
                        
    def deliver_acc(self, msg,s,H,h):
        if str(msg['FLAG'])+str(s)+str(h) not in self.RECEIVEDACC.keys():
            self.RECEIVEDACC[str(msg['FLAG'])+str(s)+str(h)]=[]
        if msg['FROM'] not in self.RECEIVEDACC[str(msg['FLAG'])+str(s)+str(h)].values():
                self.RECEIVEDACC[str(msg['FLAG'])+str(s)+str(h)].append(msg['FROM'])
                self.COUNTER[str(msg['FLAG'])+str(s)+str(H)+str(h)]=self.COUNTER[str(msg['FLAG'])+str(s)+str(H)+str(h)]+1
                if self.COUNTER[str(msg['FLAG'])+str(s)+str(H)+str(h)]>=self.faulty+1:
                    b=False
                    if str(s)+str(h) not in self.MSGSET.keys():
                         self.MSGSET[str(s)+str(h)]=[]
                    for j in self.MSGSET[str(s)+str(h)]:
                        if j[0]==str(H):
                         b=True
                         break
                    if b==False:
                        msg_temp={}
                        msg_temp['FLAG']=str('REQ')
                        self.broadcast(msg_temp,s,H,h)
                self.check(msg['FROM'], H, h)

    def deliver_req(self, msg, s,H,h):
         if str(msg['FLAG'])+str(s)+str(h) not in self.RECEIVEDREQ.keys():
            self.RECEIVEDREQ[str(msg['FLAG'])+str(s)+str(h)]=[]
         if msg['FROM'] not in self.RECEIVEDREQ[str(msg['FLAG'])+str(s)+str(h)].values():
            self.RECEIVEDREQ[str(msg['FLAG'])+str(s)+str(h)].append(msg['FROM'])
            b=False
            m=0
            if str(s)+str(h) not in self.MSGSET.keys():
                self.MSGSET[str(s)+str(h)]=[]
            for j in self.MSGSET[str(s)+str(h)]:
                 if j[0]==str(H):
                        b=True
                        m=j[1]
                        break
            if b==True:
                msg_temp={}
                msg_temp['FLAG']='FWD'
                # self.h=self.h+1 # incrementing sequence number
                self.h=self.sid
                message['FROM']=str(self.sid)
                message['S']=str(s)
                self.AL[int(msg['FROM'])].send(message,H,h)

                if str('REQ')+str(s)+str(H)+str(h) not in self.SENTREQ.keys():
                    self.SENTREQ[str('REQ')+str(s)+str(H)+str(h)]=[]
                self.SENTREQ['REQ'+str(message['S'])+str(H)+str(h)].append(str(msg['FROM']))  

    def deliver_fwd(self,msg, s, H,h):
        if str(msg['FLAG'])+str(s)+str(H)+str(h) not in self.SENTREQ.keys():
            self.SENTREQ[str(msg['FLAG'])+str(s)+str(H)+str(h)]=[]
        if msg['FROM'] in self.SENTREQ[str(msg['FLAG'])+str(s)+str(H)+str(h)].values():
            if str(msg['FLAG'])+str(s)+str(msg['MSG'])+str(h) not in self.RECEIVEDFWD.keys():
                self.RECEIVEDFWD[str(msg['FLAG'])+str(s)+str(msg['MSG'])+str(h)]=[]
            if msg['FROM'] not in self.RECEIVEDFWD[str(msg['FLAG'])+str(s)+str(msg['MSG'])+str(h) ].values():
                self.RECEIVEDFWD[str(msg['FLAG'])+str(s)+str(msg['MSG'])+str(h) ].append(str(msg['FROM']))
                self.MSGSET[str(s)+str(h)].append((H,msg['MSG']))
                HMAC=hmac.new( KEY, msg['MSG'], hashlib.sha256 )
                self.check(s, HMAC, h)

    def check(self,s,H,h):
        b=False
        if str(s)+str(h) not in self.MSGSET.keys():
            self.MSGSET[str(s)+str(h)]=[]
        for j in self.MSGSET[str(s)+str(h)]:
                if j[0]==str(H):
                    b=True
                    m=j[1]
                    break
        if b==True:
            if self.COUNTER[str('ECHO')+str(s)+str(H)+str(h)]>=self.faulty+1:
                if str('ECHO')+str(s)+str(h) not in self.SENTECHO.keys():
                    msg={}
                    msg['FLAG']='ECHO'
                    self.broadcast(msg,s,H,self.CODESET[str(s)+str(H)+str(h)][self.sid],h)
            if self.COUNTER[str('ECHO')+str(s)+str(H)+str(h)]>=len(self.ids)-self.faulty:
                if str('ACC')+str(s)+str(h) not in self.SENTACC.keys():
                    msg={}
                    msg['FLAG']='ACC'
                    self.broadcast(msg,s,H,h)
            if self.COUNTER[str('ACC')+str(s)+str(H)+str(h)]>=self.faulty+1:
                if str('ACC')+str(s)+str(h) not in self.SENTACC.keys():
                    msg={}
                    msg['FLAG']='ACC'
                    self.broadcast(msg,s,H,h)
            if self.COUNTER[str('ACC')+str(s)+str(H)+str(h)]>=len(self.ids)-self.faulty:
                msg={}
                msg['S']=s
                msg['H']=h
                self.deliver(msg)
                                
    def deliver(self,msg):
        # delivering the final message that is a dictionary
        print("-----MESSAGE DELIVERED:",self.MSGSET[str(msg['S'])+str(msg['H'])][0])
        delivered=True
