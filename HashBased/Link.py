import socket
import json
import logging
from threading import Thread

RCV_BUFFER_SIZE = 1024
KEY_SIZE = 32


class Link:
    def __init__(self, self_id, self_ip, idn, ip, proc):
        self.proc = proc
        self.self_id = self_id  # id of sending process
        self.id = idn  # id of receiving process
        self.self_ip = self_ip
        self.ip = ip
        self.key = {}

    def get_id(self):
        return self.id

    def receiver(self):
        # print("Start thread to receive messages...")
        logging.info("AUTH:Start thread to receive messages...")
        t = Thread(target=self.__receive)
        t.start()

    # This handles the message receive
    # Now the listening port is the concatenation 50/5 - 'receiving process' - 'sending process'
    def __receive(self):
        ready = False
        host = ""  # Symbolic name meaning all available interfaces
        # It uses ternary operator
        port = (
            int("50" + str(self.id) + str(self.self_id))
            if self.self_id < 10 and self.id < 10
            else int("5" + str(self.id) + str(self.self_id))
        )
        print(port)

        logging.info("AUTH:Port used for receiving: %d", port)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.s:
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.s.bind((host, port))
            self.s.listen(0)
            while True:
                conn, addr = self.s.accept()

                with conn:
                    logging.info("AUTH:Connected by %s", addr)
                    while True:
                        data = conn.recv(RCV_BUFFER_SIZE)
                        if not data:
                            break

                        parsed_data = json.loads(data.decode())

                        logging.info(
                            "AUTH: <%s, %d> -- sent this data %s",
                            self.ip,
                            self.id,
                            parsed_data,
                        )
                        t = Thread(
                            target=self.__receiving,
                            args=(parsed_data),
                        )
                        t.start()
                        if "READY" in parsed_data.values():
                             ready = True

                if ready:
                    break

            logging.info(
                "AUTH:------- SOCKET CLOSED, ME: %s,TO: %s", self.self_ip, self.ip
            )

    # The SEND opens a new socket, the port is the concatenation of 50/5- id of sending process - id of receiving process
    # Example: sending_id = 1, receiving_id = 2 ---> port = 5012
    def send(self, message):
        # The message is a dictionary built from the upper class and
        # passed to the Link class to be sent

        # It uses ternary operator
        port = (
            int("50" + str(self.self_id) + str(self.id))
            if self.self_id < 10 and self.id < 10
            else int("5" + str(self.self_id) + str(self.id))
        )

        logging.info(
            "AUTH: Port used to connect: %d to <%s,%d>", port, self.ip, self.id
        )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.connect((self.ip, port))

            parsed_data = json.dumps(message)
            self.sock.sendall(bytes(parsed_data, encoding="utf-8"))

            logging.info("AUTH: %s sent to <%s, %d>", message, self.ip, self.id)

    def __receiving(self, message):
        msg = message["MSG"]
        flag = message["FLAG"]

        if flag == "MSG":
            self.proc.receiving_msg(msg, self.id)
        elif flag == "ECHO":
            self.proc.deliver_echo(msg, flag, self.id)
        elif flag == "ACC":
            self.proc.deliver_ready(msg, flag, self.id)
        elif flag == "REQ":
            self.proc.deliver_ready(msg, flag, self.id)
        elif flag == "FWD":
            self.proc.deliver_ready(msg, flag, self.id)
