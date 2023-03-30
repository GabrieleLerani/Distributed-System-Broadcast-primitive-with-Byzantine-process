import socket
import json
import logging
from threading import Thread

RCV_BUFFER_SIZE = 1024

class Link:
    def __init__(self, self_id, self_ip, idn, ip, proc):
        self.proc = proc
        self.self_id = self_id  # id of sending process
        self.id = idn  # id of receiving process
        self.self_ip = self_ip
        self.ip = ip

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

                        print(parsed_data)
                        print(isinstance(parsed_data, dict))

                        logging.info(
                            "AUTH: <%s, %d> -- sent this data %s",
                            self.ip,
                            self.id,
                            parsed_data,
                        )
                        t = Thread(
                            target=self.__receiving,
                            args=(parsed_data,)
                        )
                        t.start()
                        # if you receive an ACC for some message M from some other process,
                        # it means that it received at least n-f ECHOs for that message M,
                        # so it is safe to close the socket with it
                        # (it received at least f+1 ECHOs from correct processes,
                        # so it is impossible that it will send a REQ message;
                        # in fact, even if it receives the same message from all the faulty processes
                        # it will not send it because they are at most f)
                        # Otherwise, if you don't receive an ACC from someone,
                        # it may mean that it did not receive the message at all,
                        # so it may ask you about the message associated to the ACC that it received
                        # (indeed, you will send / sent an ACC message to it too)
                        if "ACC" in parsed_data.values():
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
        flag = message["Flag"]

        if flag == "MSG":
            self.proc.receiving_msg(message, self.id)
        elif flag == "ECHO":
            self.proc.receiving_echo(message, self.id)
        elif flag == "ACC":
            self.proc.receiving_acc(message, self.id)
        elif flag == "REQ":
            self.proc.receiving_req(message, self.id)
        elif flag == "FWD":
            self.proc.receiving_fwd(message, self.id)
