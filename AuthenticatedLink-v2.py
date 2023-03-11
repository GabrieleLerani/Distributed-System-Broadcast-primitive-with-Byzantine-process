import socket
import hashlib
import hmac
from threading import Thread

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

RCV_BUFFER_SIZE = 1024

class AuthenticatedLink:
    def __init__(self, selfid, selfip, id, ip, proc):
        self.proc = proc
        self.selfid = selfid   #id of sending process
        self.id = id           #id of receiving process
        self.selfip = selfip
        self.ip = ip
        self.key = []

    def receiver(self):
        print("Start thread to receive messages...")
        t = Thread(target=self.__receive)
        t.start()
	
	# This handles the message receive
	# Now the listening port is the concatenation 50/5 - 'receiving process' - 'sending process'
    def __receive(self):
        host = ''  # Symbolic name meaning all available interfaces
        # It uses ternary operator
        port = int("50" + self.id + self.selfid ) if self.selfid < 10 and self.id < 10 else int("5" + self.id + self.selfid)    
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen(0)
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                while True:
                    data = conn.recv(RCV_BUFFER_SIZE)
                    if not data: break
                    paresd_data = json.loads(data.decode())
                    print(parsed_data)
                    self.__deliver(data, id)
	
	# DICTIONARY FOR KEY ??
    def __check(self, id):
        if self.key[id] == 0:
            self.key[id] = ChaCha20Poly1305.generate_key()
            self.s.sendall(self.key[id])
            self.temp = self.s.recv(RCV_BUFFER_SIZE, 0)
            if self.temp != "synACK":   #ack usato per sincronia con altro processo
                return 1
                
	# Compute the hmac of the message with a key associated to the process with self.id
	# The message is returned as a dictionary: {"MSG": message,"HMAC": hmac, "FLAG": flag}
	# The hmac is computed starting from the concatenation of flag and message
	# Example: flag = "SEND" , message = "Hello" ----> HMAC("SENDHello")
    def __auth(self, message, flag):
        self.__check(self.id)
        mess = {"MSG":message, "HMAC":hmac.new(self.key[self.id], flag+message, hashlib.sha256, "FLAG":flag ).hexdigest()}  
        return mess
	
	
	# The send open a new socket, the port is the concatenation of 50/5- id of sending process - id of receiving process
	# Example: sending_id = 1, receiving_id = 2 ---> port = 5012
	def send(self, message, flag):
		# It uses ternary operator
		port = int("50" + self.selfid + self.id) if self.selfid < 10 and self.id < 10 else int("5" + self.selfid + self.id)    
    	
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.s:
            self.s.connect((self.ip, port))
        
        # Mess is a dictionary
        mess = self.__auth(message, flag)
        parsed_data = json.dumps(mess)
        self.s.sendall(bytes(parsed_data,encoding='utf-8'))
        self.s.close()
	
	# It checks message authenticity comparing the hmac
    def __check_auth(self, message, hmac, flag, id):
		temphash = hmac.new(self.key[id], temp+message, hashlib.sha256).hexdigest()   #creazione HMAC dal messaggio contenuto in SEND,message(lista)
        return temphash == hhmac

    def __deliver(self, message, id):
        
        msg = message["MSG"]
    	hmac = message["HMAC"]
    	flag = message["FLAG"]
        
        self.__check_auth(message, hmac, flag, id)
    	
    	if flag == "SEND":   
            self.proc.deliverSend(msg, flag, self.id)
        elif flag == "ECHO":
            self.proc.deliverEcho(msg, flag, self.id)
        elif flag == "READY":
            self.proc.deliverReady(msg, flag, self.id)
