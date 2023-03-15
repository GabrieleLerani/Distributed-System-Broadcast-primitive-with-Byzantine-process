import math

import pika as pika
import sys
import AuthenticatedLink
import socket
from threading import Thread
import time
import json
import struct
import logging

SERVER_ID = "192.168.1.40"
SERVER_PORT = 5000

RCV_BUFFER_SIZE = 1024
BREAK_TIME = 0.1


class Process:
    def __init__(self):
        self.ids = []
        self.ips = []
        self.currentMSG = []
        self.selfip = 0
        self.selfid = 0
        self.AL = []
        self.sentecho = False
        self.sentready = False
        self.delivered = False
        self.echos = {}
        self.readys = {}
        self.faulty = math.floor(len(self.ids) / 3)

    def connectionToServer(self):
        # It starts a connection to the server to obtain a port number
        print("-----CONNECTING TO SERVER...-----")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_ID, SERVER_PORT))
            mess = bytes("Hello", "utf-8")
            s.sendall(mess)
            data = s.recv(RCV_BUFFER_SIZE).decode()
            #print(sys.stderr, "This is the port given by the server: " + data)
            logging.debug("PROCESS:This is the port given by the server: " + data)
        port = 5000 + int(data)
        print("-----CONNECTION TO SERVER SUCCESSFULLY CREATED-----")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
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
        
        #print(sys.stderr, "This is the list of id and ip", self.ids, self.ips)
        logging.debug("PROCESS:This is the list of id and ip", self.ids, self.ips)
        logging.info("PROCESS:Starting thread on function thread")
        print("-----GATHERED ALL THE PEERS IPS FROM THE BOOTSTRAP SERVER-----")
        print("-----STARTING SENDING OR RECEIVING MESSAGES-----")
        t = Thread(target=self.__thread)
        t.start()

    def creationLinks(self):
        # hostname = socket.gethostname()
        # IPAddr = socket.gethostbyname(hostname)

        # self.selfip = IPAddr

        self.selfip = "192.168.1.32"  # TODO remove

        self.selfid = self.ids[self.ips.index(self.selfip)]
        for i in range(0, len(self.ids)):
            self.AL.append(
                AuthenticatedLink.AuthenticatedLink(
                    self.selfid, self.selfip, self.ids[i], self.ips[i], self
                )
            )
            self.AL[i].receiver()

    def __thread(self):
        #print(sys.stderr, "Number of faulty processes is :" + str(self.faulty))
        logging.debug("PROCESS:Number of faulty processes is :" + str(self.faulty))
        while True:
            for msg in self.currentMSG:
                #print("MSG: ", msg)
                logging.debug("PROCESS:Msg in currentMSG:",msg)
                counter_echos = 0
                counter_readys = 0

                for i in self.echos.values():
                    if i == msg:
                        counter_echos += 1
                for i in self.readys.values():
                    if i == msg:
                        counter_readys += 1
               # print(
               #    "counter echos:",
               #    counter_echos,
               #     "N+f/2=",
               #    (len(self.ids) + self.faulty) / 2,
               #    "ECHOS: ",
               #    self.echos.values(),
               # )
                logging.debug("PROCESS:Counter echos:",counter_echos,"N+f/2=",(len(self.ids) + self.faulty) / 2,"ECHOS: ",self.echos.values(),)

                if (
                    counter_echos > (len(self.ids) + self.faulty) / 2
                ) and self.sentready == False:
                    self.sentready = True

                    #print("------ Starting ready part ------ ")
                    logging.info("PROCESS:------ Starting ready part ------ ")
                    # Broadcast to all a ready message
                    for i in range(len(self.ids)):
                        self.currentMSG.append(msg)
                        self.AL[i].send(msg, flag="READY")

                if counter_readys > self.faulty and self.sentready is False:
                    self.sentready = True

                    # Broadcast to all a ready message
                    for i in range(len(self.ids)):
                        self.currentMSG.append(msg)
                        self.AL[i].send(msg, flag="READY")

                if counter_readys > 2 * self.faulty and self.delivered is False:
                    self.delivered = True
                    #print(
                     #   sys.stderr,
                      #  "PROCESS:{id},{ip}".format(id=self.selfid, ip=self.selfip),
                       # "Delivered:",
                        #msg,
                    #)
                    logging.debug("PROCESS:{id},{ip}".format(id=self.selfid, ip=self.selfip), "Delivered:",msg,)
                    print("-----MESSAGE DELIVERED:-----",msg)

            # Not to destroy performance
            time.sleep(BREAK_TIME)

    # Before starting broadcast, a process reads the ip addresses and ids of
    # the other processes from its queue
    def __update(self):
        with pika.BlockingConnection(
            pika.ConnectionParameters(host=SERVER_ID)
        ) as connection:
            channel = connection.channel()

            response = channel.queue_declare(queue=str(self.selfid))
            # Get the queue length (number of not consumed messages)
            num = response.method.message_count
           # print(
           #    sys.stderr,
           #   "PROCESS:{id},{ip}".format(id=self.selfid, ip=self.selfip),
           #  "My queue length:",
           # num,
           #)
            logging.debug("PROCESS:{id},{ip}".format(id=self.selfid, ip=self.selfip),"My queue length:",num,)
            if num == 0:
                channel.close()
                return

            self.counter = 0

            def callback(ch, method, properties, body):
                # check the message ordering
                # Returns the concatenation of ip and id
                #print(sys.stderr, " [x] Received %r" % body)
                logging.debug("PROCESS: [x] Received %r" % body)
                queue_msg = body.decode("utf-8")
                temp = queue_msg.split("#")
                ip_from_queue = temp[0]
                id_from_queue = temp[1]
                if ip_from_queue not in self.ips:
                    self.ips.append(ip_from_queue)
                    self.ids.append(int(id_from_queue))
                self.counter += 1
                if self.counter == num:
                    channel.stop_consuming()
                    channel.close()

            channel.basic_consume(
                queue=str(self.selfid), on_message_callback=callback, auto_ack=True
            )
            channel.start_consuming()

    # The message is sent using authenticated link abstractions, it's a string with a flag indicating
    # the type (SEND,ECHO,READY)
    def broadcast(self, message):
        self.__update()
        for j in range(len(self.AL), len(self.ids)):
            self.AL.append(
                AuthenticatedLink.AuthenticatedLink(
                    self.selfid, self.selfip, self.ids[j], self.ips[j], self
                )
            )
            self.AL[j].receiver()
        for i in range(len(self.ids)):
            self.currentMSG.append(message)
            self.AL[i].send(message, flag="SEND")

    def deliverSend(self, msg, flag, id):
        # id == 1 checks that the delivery is computed with the sender s that by convention it's the first
        if flag == "SEND" and id == 1 and self.sentecho == False:
            # Add the message if it's not yet received
            if msg not in self.currentMSG:
                self.currentMSG.append(msg)
            self.sentecho = True
            #print(
            #   sys.stderr,
            #  "PROCESS:{id},{ip}".format(id=self.selfid, ip=self.selfip),
            # "Starting the ECHO part...",
            #)
            logging.debug("PROCESS:{id},{ip}".format(id=self.selfid, ip=self.selfip),"Starting the ECHO part...",)
            self.__update()  # If writer_id == 1 then it is correct, otherwise no
            for i in range(len(self.ids)):
                self.AL[i].send(msg, flag="ECHO")

    def deliverEcho(self, msg, flag, id):
        #print("msg,", msg, "flag", flag, "id", id)
        #print("CURRENTMSG", self.currentMSG)
        logging.debug("PROCESS:Msg,", msg, "flag", flag, "id", id)
        logging.debug("PROCESS:CURRENTMSG", self.currentMSG)
        if flag == "ECHO" and id not in self.echos:
            if msg not in self.currentMSG:
                self.currentMSG.append(msg)
            self.echos[id] = msg
            #print(
            #   sys.stderr,
            #  "--------The dicts are {echos}:".format(echos=self.echos) + "-------\n",
            #)
            logging.debug("PROCESS: --------The dicts are {echos}:".format(echos=self.echos) + "-------\n",)

    def deliverReady(self, msg, flag, id):
        #print("msg,", msg, "flag", flag, "id", id)
        #print("CURRENTMSG", self.currentMSG)
        logging.debug("PROCESS:Msg,", msg, "flag", flag, "id", id)
        logging.debug("PROCESS:CURRENTMSG", self.currentMSG)
        if flag == "READY" and id not in self.readys:
            if msg not in self.currentMSG:
                self.currentMSG.append(msg)
            self.readys[id] = msg
            #print(
            #   sys.stderr,
            #  "--------The dicts are {readys}:".format(readys=self.readys)
            # + "-------\n",
            #)
            logging.debug("PROCESS: --------The dicts are {readys}:".format(echos=self.readys) + "-------\n",)
