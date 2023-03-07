import socket
import hashlib
import hmac
from threading import Thread

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class AuthenticatedLink:
    def __init__(self, selfid, selfip, id, ip, proc):
        self.proc = proc
        self.selfid = selfid   #id del processo che invia
        self.id = id           #id del processo che riceve
        self.selfip = selfip
        self.ip = ip
        #TODO
        self.key = []

    def receiver(self):
        print("Start thread...")
        t = Thread(target=self.__receive)
        t.start()

    def __receive(self):
        host = ''  # Symbolic name meaning all available interfaces
        if self.selfid < 10 and self.id < 10:
            port = int("50" + str(self.id) + str(self.selfid))   #prima conversione in string per concatenarli e poi riconversione in int
        else:
            port = int("5" + str(self.id) + str(self.selfid))   #prima conversione in string per concatenarli e poi riconversione in int
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen(0)
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                while True:
                    data = conn.recv(1024)
                    if not data: break
                    self.__deliver(data, id)

    def __check(self, id):
        if self.key[id] == 0:
            self.key[id] = ChaCha20Poly1305.generate_key()
            self.s.sendall(self.key[id])
            self.temp = self.s.recv(1024, 0)
            if self.temp != "synACK":   #ack usato per sincronia con altro processo
                return 1

    def __auth(self, message):
        self.__check(self.id)
        mess = [message, hmac.new(self.key[self.id], message, hashlib.sha256).hexdigest()]   #creazione lista contenente lista SEND,message + HMAC
        return mess

    def send(self, message):
        if self.selfid < 10 and self.id < 10:
            port = int("50" + self.selfid + self.id)   #sono invertiti rispetto a sopra perchè prima viene inserito l'id di chi che invia e poi quello di chi riceve
        else:
            port = int("5" + self.selfid + self.id)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.s:
            self.s.connect((self.ip, port))
        mess = self.__auth(message)
        self.s.sendall(mess)
        self.s.close()

    def __check_auth(self, message, id):
        temphash = hmac.new(self.key[id], message[0], hashlib.sha256).hexdigest()   #creazione HMAC dal messaggio contenuto in SEND,message(lista)
        return temphash == message[1]

    def __deliver(self, message, id):
        self.__check_auth(message, id)
        if message[0][:4] == "SEND":   #se non funziona va messo [:3]
            self.proc.deliverSend(message[0], self.id)
        elif message[0][:4] == "ECHO":
            self.proc.deliverEcho(message[0], self.id)
        elif message[0][:5] == "READY":
            self.proc.deliverReady(message[0], self.id)