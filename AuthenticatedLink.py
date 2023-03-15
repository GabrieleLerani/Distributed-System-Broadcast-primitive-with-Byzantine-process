import socket
import hashlib
import hmac
import json
import sys
import time
from threading import Thread

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

RCV_BUFFER_SIZE = 1024
KEY_SIZE = 32


class AuthenticatedLink:
    def __init__(self, self_id, self_ip, id, ip, proc):
        self.proc = proc
        self.self_id = self_id  # id of sending process
        self.id = id  # id of receiving process
        self.self_ip = self_ip
        self.ip = ip
        self.key = {}

    def receiver(self):
        print("Start thread to receive messages...")
        t = Thread(target=self.__receive)
        t.start()

    # This handles the message receive
    # Now the listening port is the concatenation 50/5 - 'receiving process' - 'sending process'
    def __receive(self):
        host = ""  # Symbolic name meaning all available interfaces
        # It uses ternary operator
        port = (
            int("50" + str(self.id) + str(self.self_id))
            if self.self_id < 10 and self.id < 10
            else int("5" + str(self.id) + str(self.self_id))
        )

        print("Port used for receiving: " + str(port))

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.s:
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.s.bind((host, port))
            self.s.listen(0)
            conn, addr = self.s.accept()

            with conn:
                print("Connected by", addr)
                while True:
                    data = conn.recv(RCV_BUFFER_SIZE)

                    if not data:
                        break

                    parsed_data = json.loads(data.decode())
                    print(sys.stderr, self.ip, self.id, "sent this data:", parsed_data)
                    if "MSG" not in parsed_data.keys():
                        self.__add_key(parsed_data)
                        conn.sendall(b"synACK")
                    else:
                        t = Thread(target=self.__deliver, args=(parsed_data,))
                        t.start()

                        # self.__deliver(parsed_data)
                print("------ DATA", data)
            print(
                "------- SOCKET CLOSED, ME:{self_ip},TO:{ip}".format(
                    self_ip=self.self_ip, ip=self.ip
                )
            )

    def __add_key(self, key_dict):
        self.key[self.id] = key_dict["KEY"].encode("latin1")
        print(
            sys.stderr,
            self.ip,
            self.id,
            "is the one with this key: {dict}".format(dict=self.key),
        )

    def __check(self, id):
        if id not in self.key:
            self.key[id] = ChaCha20Poly1305.generate_key()
            key_to_send = {"KEY": self.key[id].decode("latin1")}
            print(
                sys.stderr, "This is what I am sending: {dict}".format(dict=key_to_send)
            )
            data = json.dumps(key_to_send)
            self.sock.sendall(data.encode())
            self.temp = self.sock.recv(RCV_BUFFER_SIZE, 0).decode()

            if self.temp != "synACK":  # Ack used for synchronization with other process
                return 1

    # Compute the hmac of the message with a key associated to the process with self.id
    # The message is returned as a dictionary: {"MSG": message,"HMAC": hmac, "FLAG": flag}
    # The hmac is computed starting from the concatenation of flag and message
    # Example: flag = "SEND" , message = "Hello" ----> HMAC("SENDHello")
    def __auth(self, message, flag):
        self.__check(self.id)
        mess = {
            "MSG": message,
            "HMAC": hmac.new(
                self.key.get(self.id, "Key not found"),
                (flag + message).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest(),
            "FLAG": flag,
        }

        print(sys.stderr, "Key generated")
        return mess

    # The send open a new socket, the port is the concatenation of 50/5- id of sending process - id of receiving process
    # Example: sending_id = 1, receiving_id = 2 ---> port = 5012
    def send(self, message, flag):
        # It uses ternary operator
        port = (
            int("50" + str(self.self_id) + str(self.id))
            if self.self_id < 10 and self.id < 10
            else int("5" + str(self.self_id) + str(self.id))
        )

        print(sys.stderr, "Port used to connect: ", str(port), "to", self.ip, self.id)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
            self.sock.connect((self.ip, port))

            # Mess is a dictionary
            mess = self.__auth(message, flag)
            parsed_data = json.dumps(mess)
            self.sock.sendall(bytes(parsed_data, encoding="utf-8"))

            print(sys.stderr, "{dict} sent to ".format(dict=mess), self.ip, self.id)

    # It checks message authenticity comparing the hmac
    def __check_auth(self, message, attached_mac, flag):
        temp_hash = hmac.new(
            self.key.get(self.id, "Key not found"),
            (flag + message).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return temp_hash == attached_mac

    def __deliver(self, message):
        msg = message["MSG"]
        attached_mac = message["HMAC"]
        flag = message["FLAG"]

        self.__check_auth(msg, attached_mac, flag)  # TODO If HMAC is incorrect, abort

        time.sleep(0.1)
        self.receiver()
        if flag == "SEND":
            self.proc.deliverSend(msg, flag, self.id)
        elif flag == "ECHO":
            self.proc.deliverEcho(msg, flag, self.id)
        elif flag == "READY":
            self.proc.deliverReady(msg, flag, self.id)
