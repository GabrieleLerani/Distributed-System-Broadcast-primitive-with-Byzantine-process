import pika as pika

import AuthenticatedLink
import socket
from threading import Thread
import time
import json
import struct

SERVER_ID = "192.168.1.17"
SERVER_PORT = 5000

RCV_BUFFER_SIZE = 1024


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
        self.echos = []
        self.readys = []
        self.faulty = len(self.ids) / 3

    def connectionToServer(self):
        # It starts a connection to the server to obtain a port number
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            #s.connect((SERVER_ID, SERVER_PORT))

            # TODO fix, it doesn't work with ngrok
            s.connect((socket.gethostbyname('4.tcp.eu.ngrok.io'), 15195))
            mess = bytes("Hello", "utf-8")
            s.sendall(mess)
            data = s.recv(RCV_BUFFER_SIZE).decode()
            print(data)

        port = 5000 + int(data)

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
                msg_len = struct.unpack('!I', len_prefix)[0]
                # receive the JSON object data
                json_data = b''
                while len(json_data) < msg_len:
                    packet = sock.recv(msg_len - len(json_data))
                    if not packet:
                        break
                    json_data += packet

                # parse the JSON object
                obj = json.loads(json_data.decode('utf-8'))

                # Add IP and ID to list
                if isinstance(obj, dict):
                    self.ids.append(obj.get("ID", "Not found"))
                    self.ips.append(obj.get("IP", "Not found"))
                # END is str so isinstance of obj returns false
                else:
                    break

        print(self.ids, self.ips)
        t = Thread(target=self.__thread)
        t.start()

    def creationLinks(self):
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)
        self.selfip = IPAddr

        # self.selfip = "192.168.1.17" TODO remove

        self.selfid = self.ids[self.ips.index(self.selfip)]
        for i in range(0, len(self.ids)):
            self.AL.append(
                AuthenticatedLink.AuthenticatedLink(
                    self.selfid, self.selfip, self.ids[i], self.ips[i], self
                )
            )
            self.AL[i].receiver()

    def __thread(self):
        while True:
            for msg in self.currentMSG:
                counter_echos = 0
                counter_readys = 0
                for i in range(len(self.echos)):
                    if self.echos[i] == msg:
                        counter_echos += 1
                for i in range(len(self.readys)):
                    if self.readys[i] == msg:
                        counter_readys += 1
                if (
                        counter_echos > (len(self.ids) + self.faulty) / 2
                ) and self.sentready == False:
                    self.sentready = True

                    # Broadcast to all a ready message
                    for i in range(len(self.ids)):
                        self.currentMSG = msg
                        self.AL[i].send(msg, flag="READY")

                if counter_readys > self.faulty and self.sentready is False:
                    self.sentready = True

                    # Broadcast to all a ready message
                    for i in range(len(self.ids)):
                        self.currentMSG = msg
                        self.AL[i].send(msg, flag="READY")

                if counter_readys > 2 * self.faulty and self.delivered is False:
                    self.delivered = True
                    print("Delivered:", msg)

            # To allow synchronization
            time.sleep(0.1)

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
            print(num)
            self.counter = 0

            def callback(ch, method, properties, body):
                # check the message ordering
                # Returns the concatenation of ip and id
                print(" [x] Received %r" % body)
                queue_msg = body.decode("utf-8")
                temp = queue_msg.split("#")
                ip_from_queue = temp[0]
                id_from_queue = temp[1]
                if ip_from_queue not in self.ips:
                    self.ips.append(ip_from_queue)
                    self.ids.append(int(id_from_queue))
                print(self.ips + self.ids)
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
        for i in range(len(self.ids)):
            self.currentMSG = message
            self.AL[i].send(message, flag="SEND")

    def deliverSend(self, msg, flag, id):
        # id == 1 checks that the delivery is computed with the sender s that by convention it's the first
        if flag == "SEND" and id == 1 and self.sentecho == False:
            # Add the message if it's not yet received
            if msg not in self.currentMSG:
                self.currentMSG.append(msg)
            self.sentecho = True
            for i in range(len(self.ids)):
                self.AL[i].send(msg, flag)
                print("hello")

    def deliverEcho(self, msg, flag, id):
        if flag == "ECHO":
            if self.echos[id] is None:
                # Add the message if it's not yet received
                if msg not in self.currentMSG:
                    self.currentMSG.append(msg)
                    self.echos[id] = msg

    def deliverReady(self, msg, flag, id):
        if flag == "READY":
            if self.readys[id] is None:
                # Add the message if it's not yet received
                if msg not in self.currentMSG:
                    self.currentMSG.append(msg)
                    self.readys[id] = msg
