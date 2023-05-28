import socket
import json
import AM.utils as utils
from threading import Thread


RCV_BUFFER_SIZE = 32768


class Link:
    def __init__(self, self_id, self_ip, idn, ip, proc):
        self.proc = proc
        self.self_id = self_id  # id of the process that is creating this instance
        self.id = idn  # id of the other process
        self.self_ip = self_ip  # ip of the process that is creating this instance
        self.ip = ip  # ip of the other process
        self.key = {}  # key exchanged between the two processes
        self.sending_port = (
            int("51" + str(self.self_id) + str(self.id))
            if self.self_id < 10 and self.id < 10
            else int("6" + str(self.self_id) + str(self.id))
        )
        self.receiving_port = (
            int("51" + str(self.id) + str(self.self_id))
            if self.self_id < 10 and self.id < 10
            else int("6" + str(self.id) + str(self.self_id))
        )
        self.written = False
        self.bytes_sent = 0

    def receiver(self):
        t = Thread(target=self.__receive)
        t.start()

    # This handles the message receive
    # Now the listening port is the concatenation 50/5 - 'receiving process' - 'sending process'
    def __receive(self):
        host = ""  # Symbolic name meaning all available interfaces
        # It uses ternary operator

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
                            print(f"Error: connection closed by <{self.id, self.ip}>")
                    num_dict = utils.count_dictionaries(received_data)

                    # if more than 1 then it's a SIGNED_VOTE_MSGS
                    # otherwise it's a VOTE message
                    if num_dict > 1:
                        json_objects = received_data.decode().split(
                            "}{"
                        )  # Split received data at each "}{"
                        json_objects = [
                            obj.strip("{}") for obj in json_objects
                        ]  # Remove braces from each object

                        for obj in json_objects:
                            try:
                                parsed_data = json.loads(
                                    "{" + obj + "}"
                                )  # Add braces back and parse JSON
                                # Process the parsed data as needed

                                t = Thread(
                                    target=self.__receiving,
                                    args=(parsed_data,),
                                )
                                t.start()
                            except json.JSONDecodeError as e:
                                print("Error decoding JSON:", e)
                                print("obj data:", obj)
                                continue
                    else:
                        parsed_data = json.loads(received_data.decode())

                        t = Thread(
                            target=self.__receiving,
                            args=(parsed_data,),
                        )
                        t.start()

    # The SEND opens a new socket, the port is the concatenation of 50/5-
    # id of sending process - id of receiving process
    # Example: sending_id = 1, receiving_id = 2 ---> port = 5012
    def send(self, message):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            while True:
                # Try Except used to repeat the connection until the other socket is opened again
                try:
                    sock.connect((self.ip, self.sending_port))

                    # mess is a dictionary that contains the original packet plus the HMAC

                    parsed_data = json.dumps(message)

                    # Split the message into chunks of size RCV_BUFFER_SIZE
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

                    break
                except ConnectionRefusedError:
                    continue

    def __receiving(self, message):
        # this is done in order to pass to the upper layer only the part that it requires
        if type(message) == list:
            message = message[0]
        self.proc.process_receive(message)
