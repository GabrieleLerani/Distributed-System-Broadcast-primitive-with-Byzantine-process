import socket
import hashlib
import hmac
import json
import logging
import EC.utils as utils
import time
from threading import Thread
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

RCV_BUFFER_SIZE = 16384
KEY_SIZE = 32

# Change to one if you want keys from file, use 0 if you want a real key exchange
# key = 1 is used to avoid connection refused error during simulation
KEY_EXCHANGE = 0


class AuthenticatedLink:
    def __init__(self, self_id, self_ip, idn, ip, proc):
        self.proc = proc
        self.self_id = self_id  # id of the process that is creating this instance
        self.id = idn  # id of the other process
        self.self_ip = self_ip  # ip of the process that is creating this instance
        self.ip = ip  # ip of the other process
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
        self.written = False  # used to avoid rewriting evaluation checkpoint
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

    def get_id(self):
        return self.self_id

    def receiver(self):
        t = Thread(target=self.__receive)
        t.start()

    # This handles the message receive
    # Now the listening port is the concatenation 50/5 - 'receiving process' - 'sending process'
    def __receive(self):
        host = ""  # Symbolic name meaning all available interfaces

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
                            pass
                    parsed_data = {}
                    if len(received_data) != 0:
                        for obj in utils.decode_json(received_data.decode()):
                            parsed_data = obj

                        if not self.written:
                            start_time = time.time() * 1000
                            logging.info(
                                "----- EVALUATION CHECKPOINT: message receiving, time: %s -----",
                                start_time,
                            )
                            self.written = True

                        logging.info("Message received by %s: %s", self.ip, parsed_data)

                        # Receive and store the key
                        if "FLAG" not in parsed_data.keys():
                            self.__add_key(parsed_data)
                            conn.sendall(b"synACK")
                        else:
                            t = Thread(
                                target=self.__receiving,
                                args=(parsed_data,),
                            )
                            t.start()

    def __add_key(self, key_dict):
        self.key[self.id] = key_dict["KEY"].encode("latin1")

        logging.info(
            "AUTH: <%s, %d> is the one with this key: %s",
            self.ip,
            self.id,
            self.key,
        )

    # check if there is the key for the other process
    def __check(self, sock, idn):
        # A process sends a key only if it is identified by a lower id resepect to receiver
        if idn not in self.key and self.self_id <= idn:
            self.key[idn] = ChaCha20Poly1305.generate_key()

            key_to_send = {"KEY": self.key[idn].decode("latin1")}
            logging.info("AUTH: Key generated")

            data = json.dumps(key_to_send)
            sock.sendall(data.encode())
            temp = sock.recv(RCV_BUFFER_SIZE, 0).decode()

            if temp != "synACK":  # Ack used for synchronization with other process
                return 1

    # Compute the hmac of the message with the key exchanged
    # The message is returned as a dictionary: {"FLAG": flag, "MSG": message, ... "HMAC": hmac}
    # The hmac is computed starting from the concatenation of all the fields in the message
    def __auth(self, sock, message):
        self.__check(sock, self.id)

        # This creates the string that will be authenticated
        hmac_input = ""
        for value in message.values():
            hmac_input += str(value)
        # This creates the message that will be sent

        mess = {}
        dict_hmac = {
            "HMAC": hmac.new(
                self.key[self.id],
                # self.key.get(self.id, "Key not found"),
                hmac_input.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest(),
        }
        for key in message.keys():
            dict_temp = {
                key: message[key]
            }  # Adding to the dictionary all the field that
            mess.update(dict_temp)  # were inside the original message
        mess.update(dict_hmac)  # Adding to it the HMAC just computed

        return mess

    # SEND opens a new socket, the port is the concatenation of 50/5-
    # id of sending process - id of receiving process
    # Example: sending_id = 1, receiving_id = 2 ---> port = 5012
    def send(self, message):
        # It uses ternary operator

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            while True:
                # Try Except used to repeat the connection until the other socket is opened again
                try:
                    self.sock.connect((self.ip, self.sending_port))

                    # mess is a dictionary that contains the original packet plus the HMAC
                    mess = self.__auth(self.sock, message)

                    parsed_data = json.dumps(mess)

                    # Split the message into chunks of size RCV_BUFFER_SIZE
                    chunks = [
                        parsed_data[i : i + RCV_BUFFER_SIZE]
                        for i in range(0, len(parsed_data), RCV_BUFFER_SIZE)
                    ]

                    # Send each chunk sequentially
                    for chunk in chunks:
                        data = bytes(chunk, encoding="utf-8")
                        self.sock.sendall(data)

                        # takes into account byte sent
                        self.bytes_sent += len(data)

                    logging.info("%s sent to <%s,%d>", mess, self.ip, self.id)
                    break

                except:
                    return

    def __check_auth(self, message):
        # This creates the string that should match with the HMAC

        hmac_input = ""

        for value in message.values():
            if value != message["HMAC"]:
                hmac_input += str(value)

        temp_hash = hmac.new(
            self.key[self.id],
            hmac_input.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        # The HMAC field is always present in the Authenticated Link implementation
        return temp_hash == message["HMAC"]

    def __receiving(self, message):
        if not self.__check_auth(message):
            logging.info("--- Authenticity check failed for %s", message)
            print("Authenticity check failed")
            return

        # This is the only part of the function that must be changed when using different algorithms

        # this is done in order to pass to the upper layer only the part that it requires
        # indeed, the HMAC is removed because it is useful only for this level
        message.pop("HMAC", None)

        self.proc.process_receive(message)
