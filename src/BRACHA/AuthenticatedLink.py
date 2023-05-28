import socket
import hashlib
import hmac
import json
import logging
from threading import Thread
import threading
import time
from typing import Any

import BRACHA.utils as utils


from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

RCV_BUFFER_SIZE = 8192
KEY_SIZE = 32
KEY_EXCHANGE = 0  # 1


class AuthenticatedLink:
    def __init__(self, self_id, self_ip, idn, ip, proc):
        self.proc = proc
        self.self_id = self_id  # id of sending process
        self.id = idn  # id of receiving process
        self.self_ip = self_ip
        self.ip = ip
        self.key = {}
        self.sending_port = (
            int("50" + str(self.self_id) + str(self.id))
            if self.self_id < 10 and self.id < 10
            else int("5" + str(self.self_id) + str(self.id))
        )
        self.receiving_port = (
            int("50" + str(self.id) + str(self.self_id))
            if self.self_id < 10 and self.id < 10
            else int("5" + str(self.id) + str(self.self_id))
        )
        self.written = False
        self.bytes_sent = 0

    def key_exchange(self):
        if KEY_EXCHANGE == 1:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                while True:
                    # Try Except used to repeat the connection until the other socket is opened again
                    try:
                        self.sock.connect((self.ip, self.sending_port))

                        self.__check(self.id, self.sock)

                        break
                    except ConnectionRefusedError:
                        continue
        else:
            self.key[self.id] = utils.get_key(self.self_id, self.id)

    def receiver(self):
        logging.info("AUTH:Start thread to receive messages...")
        t = Thread(target=self.__receive)
        t.start()

    # This handles the message receive
    # Now the listening port is the concatenation 50/5 - 'receiving process' - 'sending process'
    def __receive(self):
        host = ""  # Symbolic name meaning all available interfaces

        logging.info("AUTH:Port used for receiving: %d", self.receiving_port)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.s:
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.s.bind((host, self.receiving_port))
            self.s.listen(1000)

            while True:
                conn, addr = self.s.accept()

                with conn:
                    received_data = b""
                    while True:
                        try:
                            data = conn.recv(RCV_BUFFER_SIZE)

                            if not data:
                                break
                            received_data += data
                        except ConnectionResetError:
                            print("Connection reset by peer")
                            pass

                    if len(received_data) != 0:
                        parsed_data = {}
                        try:
                            parsed_data = json.loads(received_data.decode())
                        except json.JSONDecodeError:
                            print("Decode Error: data too long")

                        if not self.written:
                            start_time = time.time() * 1000

                            logging.info(
                                "----- EVALUATION CHECKPOINT: message receiving, time: %s -----",
                                start_time,
                            )

                            self.written = True

                        logging.info(
                            "AUTH: <%s, %d> -- sent this data %s",
                            self.ip,
                            self.id,
                            parsed_data,
                        )

                        # Useful for performance evaluation, upon the arrival of the first
                        # message it starts timer to monitor execution time

                        if "MSG" not in parsed_data.keys():
                            self.__add_key(parsed_data)
                            conn.sendall(b"synACK")

                        else:
                            t = Thread(
                                target=self.__deliver,
                                args=(parsed_data, threading.currentThread()),
                            )
                            t.start()

                        logging.info("AUTH:Received DATA: %s", data)

    def __add_key(self, key_dict):
        # self.key[self.id] = utils.get_key(self.self_id, self.id)
        self.key[self.id] = key_dict["KEY"].encode("latin1")

        logging.info(
            "AUTH: <%s, %d> is the one with this key: %s", self.ip, self.id, self.key
        )

    def __check(self, sock, idn):
        if idn not in self.key and self.self_id <= idn:
            self.key[idn] = ChaCha20Poly1305.generate_key()

            key_to_send = {"KEY": self.key[idn].decode("latin1")}
            logging.info("AUTH: Key generated")
            logging.info("AUTH: This is what I am sending: %s", key_to_send)

            data = json.dumps(key_to_send)
            sock.sendall(data.encode())
            temp = sock.recv(RCV_BUFFER_SIZE, 0).decode()

            if temp != "synACK":  # Ack used for synchronization with other process
                return 1

    # Compute the hmac of the message with a key associated to the process with self.id
    # The message is returned as a dictionary: {"MSG": message,"HMAC": hmac, "FLAG": flag}
    # The hmac is computed starting from the concatenation of flag and message
    # Example: flag = "SEND" , message = "Hello" ----> HMAC("SENDHello")
    def __auth(self, sock, message):
        self.__check(sock, self.id)
        mess = {
            "MSG": message["MSG"],
            "HMAC": hmac.new(
                self.key.get(self.id, "Key not found"),
                (message["FLAG"] + message["MSG"]).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest(),
            "FLAG": message["FLAG"],
        }

        return mess

    # The send open a new socket, the port is the concatenation of 50/5- id of sending process - id of receiving process
    # Example: sending_id = 1, receiving_id = 2 ---> port = 5012
    def send(self, message):
        # It uses ternary operator

        logging.info(
            "AUTH: Port used to connect: %d to <%s,%d>",
            self.sending_port,
            self.ip,
            self.id,
        )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            while True:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.connect((self.ip, self.sending_port))

                    # Mess is a dictionary
                    mess = self.__auth(sock, message)
                    parsed_data = json.dumps(mess)

                    # split big message into small chunks
                    chunks = [
                        parsed_data[i : i + RCV_BUFFER_SIZE]
                        for i in range(0, len(parsed_data), RCV_BUFFER_SIZE)
                    ]

                    # Send each chunk sequentially
                    for chunk in chunks:
                        data = bytes(chunk, encoding="utf-8")
                        sock.sendall(data)

                        # takes into account byte sent
                        self.bytes_sent += len(data)

                    logging.info("AUTH: %s sent to <%s, %d>", mess, self.ip, self.id)
                    break
                except:
                    continue

    # It checks message authenticity comparing the hmac
    def __check_auth(self, message):
        try:
            temp_hash = hmac.new(
                self.key.get(self.id, "Key not found"),
                (message["FLAG"] + message["MSG"]).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            return temp_hash == message["HMAC"]
        except TypeError as e:
            print("TypeError:", e.args)

    def __deliver(self, message, t):
        flag = message["FLAG"]

        if not self.__check_auth(message):
            logging.info("--- Authenticity check failed for %s", message)
            print("Authenticity check failed")
            return

        message.pop("HMAC", None)

        if flag == "SEND":
            self.proc.deliver_send(message, self.id)
        elif flag == "ECHO":
            self.proc.deliver_echo(message, self.id)
        elif flag == "READY":
            self.proc.deliver_ready(message, self.id)
