import AuthenticatedLink
from threading import Thread
import socket

class Process:
    def __init__(self):
        self.ids = []
        self.ips = []
        self.currentMSG = []
        self.id = 0
        self.processes = []
        self.AL = []
        for i in range(0, len(self.processes)):
            self.AL.append(AuthenticatedLink.AuthenticatedLink(self.id, self.processes[i][0], self, self.processes[i][1]))
        self.sentecho = False
        self.sentready = False
        self.delivered = False
        self.echos = []
        self.readys = []
        self.faulty = len(self.processes) / 3
    #    thread = Thread(target=self.__thread)
    #    thread.run()

    def conn(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.s:
            self.s.connect(('192.168.1.14', 5000))
            mess = bytes("Hello", "utf-8")
            self.s.sendall(mess)
            data = self.s.recv(1024)
        port = 5000 + int(data)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
            self.sock.connect(('192.168.1.14', port))
            mess = bytes("Hello", "utf-8")
            self.sock.sendall(mess)
            if self.sock.recv(1024).decode("utf-8") == "IDS":
                while 1:
                    id = self.sock.recv(1024).decode("utf-8")
                    if id == "IPS":
                        break
                    self.ids.append(id)
                    self.sock.sendall(bytes(id, "utf-8"))
                while 1:
                    ip = self.sock.recv(1024).decode("utf-8")
                    if ip == "END":
                        break
                    self.ips.append(ip)
                    self.sock.sendall(bytes(ip, "utf-8"))
        print(self.ids, self.ips)

    def __thread(self):
        while True:   #migliorare l'efficienza
            for msg in self.currentMSG:
                counterEchos = 0
                counterReadys = 0
                for i in range(len(self.processes)):
                    if self.echos[i] == msg:
                        counterEchos += 1
                    if self.readys[i] == msg:
                        counterReadys += 1
                if (counterEchos > (len(self.processes) + self.faulty) / 2) and self.sentready == False:
                    self.sentready = True
                    self.broadcast("READY", msg)
                if counterReadys > self.faulty and self.sentready == False:
                    self.sentready = True
                    self.broadcast("READY", msg)
                if counterReadys > 2 * self.faulty and self.delivered == False:
                    self.delivered = True
                    print("Delivered")

    def broadcast(self, flag, message):
        for i in range(len(self.processes)):
            self.currentMSG = message
            self.AL[i].send(flag + message)

    def deliverSend(self, message, id):
        if message[0][:4] == "SEND" and id == 1 and self.sentecho == False:   #lista message contenente lista SEND,message + stringa HMAC
            if message[5:] not in self.currentMSG:
                self.currentMSG.append(message[5:])   #aggiunta del messaggio in caso non sia all'interno di quelli ricevuti
            self.sentecho = True
            for i in range(len(self.processes)):
                self.AL[i].send("ECHO" + message[5:])

    def deliverEcho(self, message, id):
        if self.echos[id] == None:
            if message[5:] not in self.currentMSG:
                self.currentMSG.append(message[5:])   #aggiunta del messaggio in caso non sia all'interno di quelli ricevuti
            self.echos[id] = message[5:]


