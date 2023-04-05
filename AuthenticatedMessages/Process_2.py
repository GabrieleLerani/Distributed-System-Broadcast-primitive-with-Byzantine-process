import math
import Link
import pika as pika
import socket
from threading import Thread
import json
import struct
import logging
from Crypto.PublicKey import RSA
from sys import platform
from hashlib import sha512
import AuthenticatedLink

SERVER_ID = "localhost"
SERVER_PORT = 5000

KDS_IP = "localhost"
KDS_PORT = 8080

RCV_BUFFER_SIZE = 1024
BREAK_TIME = 0.1

BROADCASTER_ID = 1

PLACEHOLDER = "vote_msg"


class Process:
    def __init__(self):
        self.ids = []
        self.ips = []
        self.signed_vote_messages_container = []
        # self.signed_vote_messages_container.append(0) # to avoid index out of range problems or no intialize structure errors
        self.checked_indexes = []
        self.selfip = 0
        self.selfid = 0
        self.L = []
        self.AL = []
        self.start = 0
        self.key_gen = False
        self.keyPair = None
        self.public_keys = {}
        self.delivered = False
        self.f = math.floor(len(self.ids) / 3)   # f<N/3 condition to protocol correctness
        
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
        t = Thread(target=self.listening_thread)
        t.start()

    def creation_links(self):
        # binding my informations
        
        # checking os
        if platform == "linux" or platform == "linux2":
            hostname="localhost" # TODO dummy setting hostname until find silution for that
        else:
            hostname = socket.gethostname()

        IPAddr=socket.gethostbyname(hostname)
        self.selfip = IPAddr
        self.selfid = self.ids[self.ips.index(self.selfip)]
        # creating links 
        for i in range(0, len(self.ids)):
            # init links
            self.L.append(
                Link.Link(
                    self.selfid, self.selfip, self.ids[i], self.ips[i],self,
                )
            )
            # setting up links
            self.L[i].build_Link_r()
            self.L[i].build_Link_s()
        for i in range(0, len(self.ids)):
            self.AL.append(
                AuthenticatedLink.AuthenticatedLink(
                    self.selfid, self.selfip, self.ids[i], self.ips[i], self
                )
            )
            self.AL[i].receiver()
        logging.info("PROCESS:links successfully created")
        # init data structure for processes's links and signed vote messages
        for p in range(1,len(self.ids)+1):
            self.signed_vote_messages_container.append({})
            for id in range(1,len(self.ids)+1):
                self.signed_vote_messages_container[p][str(id)]={}
        logging.info("PROCESS:data structures for processes successfully created")
            
    def listening_thread(self):
        # checking for condition assuming only one broadcast round
        i=1
        while True:
            if i not in self.checked_indexes:
                final_msg.clear()
                final_msg={}
                final_msg_dict=self.count(i)
                final_msg_dict['TYPE']=2
                final_msg_dict['FROM']=str(self.selfid)
                if final_msg_dict.get('GO'):
                    self.broadcast(final_msg_dict)
                    self.deliver(final_msg_dict['MSG'])
                    logging.info("PROCESS:-----ENDING PROTOCOL--> AUTHENTICATED MESSAGES BROADCAST-----")
                    logging.info("PROCESS:-----SUCCESSFULL EXIT-----")
                    break
                if len(self.signed_vote_messages_container[i])!=0:
                    self.checked_indexes.append(i)
            time.sleep(BREAK_TIME)
            i=i+1
            if i== len(self.ids):
                i=1
  
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
                    self.L.append(
                        Link.Link(
                            self.selfid,
                            self.selfip,
                            self.ids[len(self.ids) - 1],
                            self.ips[len(self.ips) - 1],
                            self,
                        )
                    )
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
                    self.L[len(self.L)-1].build_Link_r()
                    self.L[len(self.L)-1].build_Link_s()
                    # init data structure for process's link
                    logging.info("PROCESS:links for new incoming process successfully created")
                    self.signed_vote_messages_container.append({})

                    for id in range(1,len(self.ids)+1):
                        self.signed_vote_messages_container[len(self.ids)][str(id)]={}
                    
                    logging.info("PROCESS:data structures for new incoming process successfully created")
                    # updating all the other processes data structure

                    for p in range(1,len(self.ids)):
                        self.signed_vote_messages_container[p][str(len(self.ids)-1)]={}
                    logging.info("PROCESS:data structures of processes for new incoming process successfully updated")

                    
                self.counter += 1
                if self.counter == num:
                    channel.stop_consuming()
                    channel.close()

            channel.basic_consume(
                queue=str(self.selfid), on_message_callback=callback, auto_ack=True
            )
            channel.start_consuming()
 
    def broadcast(self, message):
        # broadcasting messages to all processes
        self.__update()   # updating receiving side links
        # TODO adding signature here if all the messages have to be signed
        # marshal message
        if self.start == 0 and self.selfid == BROADCASTER_ID:
            mess = {}
            mess['TYPE'] = 0
            msg_temp = message
            message = mess
            self.start = 1
            logging.info("PROCESS:marshalling first broadcast message fro the broadcaster")

        match message.get('TYPE'):
        # marshal message
            case 0:
                msg = {}
                msg['TYPE'] = 0
                msg['FLAG'] = "PROPOSE"
                msg['MSG'] = msg_temp
                msg['FROM'] = BROADCASTER_ID
                for j in range(0, len(self.ids)):
                    #self.L[j].link_send(msg) 
                    self.adapter(j, msg, 'B')   # adapter pattern to remain consistent
                self.barrier.wait() # to remain consistent
                logging.info("PROCESS:Message:%s,broadcasted successfully", message)
            case 1:
                msg = {}
                msg['FLAG'] = "VOTE"
                msg['MSG'] = message.get('MSG')
                msg['SIGN'] = self.make_signature(message.get('MSG'))
                msg['TYPE'] = 1
                msg['FROM'] = self.selfid
                for j in range(0, len(self.ids)):
                    self.L[j].link_send(msg)   
                logging.info("PROCESS:Message:%s,re-broadcasted successfully", message)
            case 2:
                for j in range(0, len(self.ids)):
                    self.L[j].link_send(message)     
                logging.info("PROCESS:signed vote messages:%s,broadcasted successfully", message.get('MSG'))
            case _:
                logging.info("PROCESS:ERROR:Cannot send a message of type undefined")
        
    def adapter(self, j, msg, flag, flag_a='NULL', idn='NULL'):
        match flag:
            case 'B':
                self.AL[j].send(msg['MSG'], flag="SEND")
            case 'R':
                msg_pack = {}
                msg_pack['TYPE'] = 0
                msg_pack['FLAG'] = "PROPOSE"
                msg_pack['MSG'] = msg
                msg_pack['FROM'] = BROADCASTER_ID

                if flag_a == "SEND" and idn == 1:
                    # Add the message if it's not yet received
                    if self.selfid == BROADCASTER_ID:
                        self.barrier.wait()
                    else:
                        self.__update()  # If writer_id == 1 then it is correct, otherwise no
                # returning to the standard link flow
                self.L[j].receive(msg)

            case _: 
                logging.info("PROCESS:ERROR:Cannot send a message of type undefined")

    def process_receive(self, msg):
        # receive messages from the underlying pppl
        match msg.get('TYPE'):
            case 0:
                logging.info("PROCESS:Received a message of type 0")

                if msg.get('FROM') == BROADCASTER_ID and msg.get('FLAG') == "PROPOSE":
                    msg['TYPE'] = 1
                    self.broadcast(msg)
            case 1:
                logging.info("PROCESS:Received a message of type 1")

                if msg.get('FLAG') == "VOTE" and self.check_signature(msg.get('MSG'), msg.get('SIGN'), msg.get('FROM')):
                        self.signed_vote_messages_container[self.selfid][str(msg.get('FROM'))]['MSG'] = msg.get('MSG')
                        self.signed_vote_messages_container[self.selfid][str(msg.get('FROM'))]['SIGN'] = msg.get('SIGN')
                else:

                    if msg.get('FLAG') != "VOTE":
                        logging.info("PROCESS:Wrong flag received %s", msg.get('FLAG'))

                    else:
                        logging.info("PROCESS:Authentication error")


            case 2:
                logging.info("PROCESS:Received a message of type 2")
                counter = 0

                if not delivered:
                    for id in list(msg['keys'].values()):
                        if self.check_signature(msg['keys'][str(id)+PLACEHOLDER]['MSG'],msg['keys'][str(id)+PLACEHOLDER]['SIGN']):
                            counter=counter+1
                        if counter==len(self.ids)-f:
                            self.signed_vote_messages_container[msg.get('FROM')]=msg
            case _:
                logging.info("PROCESS:ERROR:Received a message of type undefined")
  
    def check_signature(self,message,signature,idn):
        # checking signature for received signed vote messages
        if str(idn) not in self.public_keys.keys():# maybe list
            logging.info("PROCESS:Calling KDS to get public key")
            self.public_keys[str(idn)]={}# initialize dictionary for public keys of process id=idn
            temp_dict=self.connection_to_KDS(idn, 0)
            self.public_keys[str(idn)]['N']=temp_dict['KEY']['N']
            self.public_keys[str(idn)]['E']=temp_dict['KEY']['E']
        msg = bytes(message,'utf-8')
        hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
        hashFromSignature = pow(signature, self.public_keys[str(idn)]['E'], self.public_keys[str(idn)]['N'])
        logging.info("PROCESS:Signature check exit:<%b>", hash == hashFromSignature)
        return hash==hashFromSignature
        
    def make_signature(self,message):
        # generating keys
        if not self.key_gen:
            logging.info("PROCESS:Calling KDS to get key pair")
            self.key_gen=True
            self.keyPair=self.connection_to_KDS(self.selfid, 1)
        else:
            logging.info("PROCESS:Key already generated")
        # sign
        msg = bytes(message,'utf-8')
        hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
        signature = pow(hash, self.keyPair.d, self.keyPair.n)
        logging.info("PROCESS:Signature:<%s>", hex(signature))
        return hex(signature)
    
    def connection_to_KDS(self,idn,typ):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.connect((KDS_IP, KDS_PORT))
                logging.info("PROCESS:Connecting to KDS")
                # getting key pair from KDS
                pack ={}
                pack['FROM']=idn
                pack['TYPE']=typ
                send_pack = json.dumps(pack)
                sock.sendall(send_pack.encode())
                data= sock.recv(RCV_BUFFER_SIZE)
                parsed_data=json.loads(data.decode())
                return parsed_data.get('KEY')

    def count(self,i):
        # counting if a safe vote message sats the condition
        checked_msgs=[]
        for id in range(1,len(self.signed_vote_messages_container[i])+1):
            current_dict.clear() # cleaning the dictionary
            current_dict={} # container
            current_dict['keys']={} # container into the current_dict container that contains keys_id of the processes that actually signed this current msg to be delivered
            counter=0
            current_dict['GO'] = False # barrier flag to go ahead or not
            current_msg=self.signed_vote_messages_container[i][str(id)]['MSG']
            if current_msg not in checked_msgs:
                current_dict['MSG']=current_msg
                for j in range(1,len(self.signed_vote_messages_container[i])+1): # comparing with the others to count
                    other_msg=self.signed_vote_messages_container[i][str(j)]['MSG']
                    if current_msg == other_msg:
                        current_dict['keys'][str(j)]=str(j)
                        current_dict['keys'][str(j)+PLACEHOLDER]={} # new dict for each id to know the pair <msg,signed_msg>; the +vote_msg string to avoid overwriting the prec line
                        current_dict['keys'][str(j)+PLACEHOLDER]['MSG']=other_msg
                        current_dict['keys'][str(j)+PLACEHOLDER]['SIGN']=self.signed_vote_messages_container[i][str(j)]['SIGN']
                        counter=counter+1
                    if counter==(len(self.ids)-self.f):
                        current_dict['GO']=True
                        return current_dict
                checked_msgs.append(current_msg)
        return current_dict
   
    def deliver(self,message):
        # delivering the final message 
        print("-----MESSAGE DELIVERED:",message,"-----")
        delivered=True