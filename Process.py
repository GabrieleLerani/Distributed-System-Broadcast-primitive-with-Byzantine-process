import pika as pika

import AuthenticatedLink
import socket

SERVER_ID = '192.168.1.14'

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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.s:
            self.s.connect((SERVER_ID, 5000))
            mess = bytes("Hello", "utf-8")
            self.s.sendall(mess)
            data = self.s.recv(1024)
        port = 5000 + int(data)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
            self.sock.connect((SERVER_ID, port))
            mess = bytes("Hello", "utf-8")
            self.sock.sendall(mess)
            if self.sock.recv(1024).decode("utf-8") == "IDS":
                while 1:
                    id = self.sock.recv(1024).decode("utf-8")
                    if id == "IPS":
                        break
                    self.ids.append(int(id))   #convertito in int perchè AL utilizza int
                    self.sock.sendall(bytes(id, "utf-8"))
                while 1:
                    ip = self.sock.recv(1024).decode("utf-8")   #indirizzi ip sono lasciati in string
                    if ip == "END":
                        break
                    self.ips.append(ip)
                    self.sock.sendall(bytes(ip, "utf-8"))

    def creationLinks(self):
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)
        self.selfip = IPAddr
        self.selfid = self.ids[self.ips.index(self.selfip)]
        for i in range(0, len(self.ids)):
            self.AL.append(AuthenticatedLink.AuthenticatedLink(self.selfid, self.selfip, self.ids[i], self.ips[i], self))
            self.AL[i].receiver()

    def __thread(self):
        while True:
            for msg in self.currentMSG:
                counterEchos = 0
                counterReadys = 0
                for i in range(len(self.ids)):
                    if self.echos[i] == msg:
                        counterEchos += 1
                    if self.readys[i] == msg:
                        counterReadys += 1
                if (counterEchos > (len(self.ids) + self.faulty) / 2) and self.sentready == False:
                    self.sentready = True
                    self.broadcast(msg, "READY")
                if counterReadys > self.faulty and self.sentready == False:
                    self.sentready = True
                    self.broadcast(msg, "READY")
                if counterReadys > 2 * self.faulty and self.delivered == False:
                    self.delivered = True
                    print("Delivered")

    def __update(self):
        connection = pika.BlockingConnection(pika.ConnectionParameters(host='192.168.1.14'))
        channel = connection.channel()

        channel.queue_declare(queue='gia')

        def callback(ch, method, properties, body):
            print(" [x] Received %r" % body)

        channel.basic_consume(queue='gia', on_message_callback=callback, auto_ack=True)
        channel.start_consuming()

        channel.close()

    def broadcast(self, message, flag="SEND"):
        self.__update()
        for i in range(len(self.ids)):
            self.currentMSG = message
            self.AL[i].send(flag, message)

    def deliverSend(self, message, id):
        if message[0][:4] == "SEND" and id == 1 and self.sentecho == False:   #lista message contenente lista SEND,message + stringa HMAC
            if message[5:] not in self.currentMSG:
                self.currentMSG.append(message[5:])   #aggiunta del messaggio in caso non sia all'interno di quelli ricevuti
            self.sentecho = True
            for i in range(len(self.ids)):
                self.AL[i].send("ECHO" + message[5:])

    def deliverEcho(self, message, id):
        if self.echos[id] == None:
            if message[5:] not in self.currentMSG:
                self.currentMSG.append(message[5:])   #aggiunta del messaggio in caso non sia all'interno di quelli ricevuti
            self.echos[id] = message[5:]


