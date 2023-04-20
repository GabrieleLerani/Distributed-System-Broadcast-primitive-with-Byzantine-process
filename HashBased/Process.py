import hashlib
import pika as pika
import AuthenticatedLink
import socket
import threading
import json
import struct
import logging
import math

SERVER_ID = "192.168.1.41"
SERVER_PORT = 5000

RCV_BUFFER_SIZE = 2048
BREAK_TIME = 0.1


class Process:
    def __init__(self):
        # Sequence number attached to each message
        self.h = 0
        self.id = 0
        self.ips = []
        self.ids = []
        self.AL = []
        # messages received
        self.msg = []
        self.MsgSets = {}
        # both the variable echos are lists because we need only the tracking of previous echos,
        # not the association with other values
        # in order not to count the same echo twice
        self.echos_rec = []
        # in order not to send the same echo twice
        self.echos_sent = []
        # both the variable accs are lists because we need only the tracking of previous echos,
        # not the association with other values
        self.accs_rec = []
        self.accs_sent = []

        self.reqs_rec = []
        self.reqs_sent = []

        self.fwds_rec = []

        self.faulty = 0
        # counter of echos of a specific message received
        self.echo_counter = {}
        self.acc_counter = {}

    def connection_to_server(self):
        # It starts a connection to the server to obtain a port number
        print("-----CONNECTING TO SERVER...-----")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.connect((SERVER_ID, SERVER_PORT))
            mess = bytes("Hello", "utf-8")
            s.sendall(mess)
            data = s.recv(RCV_BUFFER_SIZE).decode()
            # print(sys.stderr, "This is the port given by the server: " + data)
            logging.debug("PROCESS:This is the port given by the server: %s", data)
        port = 5000 + int(data)
        print("-----CONNECTION TO SERVER SUCCESSFULLY CREATED-----")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.connect((SERVER_ID, port))
            mess = bytes("Hello", "utf-8")
            sock.sendall(mess)
            while True:
                # receive the length prefix (4 bytes in network byte order)
                len_prefix = sock.recv(4)
                if not len_prefix:
                    break

                # unpack the length prefix into an integer
                msg_len = struct.unpack("!I", len_prefix)[0]
                # receive the JSON object data
                json_data = b""
                while len(json_data) < msg_len:
                    packet = sock.recv(msg_len - len(json_data))
                    if not packet:
                        break
                    json_data += packet

                # parse the JSON object
                obj = json.loads(json_data.decode("utf-8"))

                # Add IP and ID to list
                if isinstance(obj, dict):
                    self.ids.append(obj.get("ID", "Not found"))
                    self.ips.append(obj.get("IP", "Not found"))
                # END is str so isinstance of obj returns false
                else:
                    break

        logging.debug("PROCESS: id list: %s,ip list %s", self.ids, self.ips)
        logging.info("PROCESS:Starting thread on function thread")
        print("-----GATHERED ALL THE PEERS IPS FROM THE BOOTSTRAP SERVER-----")
        print("-----STARTING SENDING OR RECEIVING MESSAGES-----")

    def creation_links(self):
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)

        self.selfip = IPAddr

        # self.selfip = "192.168.1.x"  # TODO remove

        self.selfid = self.ids[self.ips.index(self.selfip)]
        self.barrier = threading.Barrier(parties=2)
        for i in range(0, len(self.ids)):
            self.AL.append(
                AuthenticatedLink.AuthenticatedLink(
                    self.selfid, self.selfip, self.ids[i], self.ips[i], self
                )
            )
            self.AL[i].receiver()

    # Before starting broadcast, a process reads the ip addresses and ids of
    # the other processes from its queue
    def update(self):
        with pika.BlockingConnection(
            pika.ConnectionParameters(host=SERVER_ID)
        ) as connection:
            channel = connection.channel()

            response = channel.queue_declare(queue=str(self.selfid))
            # Get the queue length (number of not consumed messages)
            num = response.method.message_count

            logging.info(
                "PROCESS: %d,%s --- My queue length: %d", self.selfid, self.selfip, num
            )

            if num == 0:
                channel.close()
                return

            self.counter = 0

            def callback(ch, method, properties, body):
                logging.info("PROCESS: [x] Received %r", body)
                queue_msg = body.decode("utf-8")
                temp = queue_msg.split("#")
                ip_from_queue = temp[0]
                id_from_queue = temp[1]
                if ip_from_queue not in self.ips:
                    self.ips.append(ip_from_queue)
                    self.ids.append(int(id_from_queue))
                    self.AL.append(
                        AuthenticatedLink.AuthenticatedLink(
                            self.selfid,
                            self.selfip,
                            self.ids[len(self.ids) - 1],
                            self.ips[len(self.ips) - 1],
                            self,
                        )
                    )
                    self.AL[len(self.AL) - 1].receiver()
                self.counter += 1
                if self.counter == num:
                    channel.stop_consuming()
                    channel.close()

            channel.basic_consume(
                queue=str(self.selfid), on_message_callback=callback, auto_ack=True
            )
            channel.start_consuming()

    def broadcast(self, message):
        self.update()
        self.faulty = math.floor((len(self.ids) - 1) / 3)
        for j in range(len(self.AL), len(self.ids)):
            self.AL.append(
                AuthenticatedLink.AuthenticatedLink(
                    self.selfid,
                    self.selfip,
                    self.ids[j],
                    self.ips[j],
                    self,
                )
            )
            self.AL[j].receiver()
        packet = {"Flag": "MSG", "Source": self.selfid, "Message": message, "SequenceNumber": self.h}
        for i in range(len(self.AL)):
            self.AL[i].send(packet)
        self.barrier.wait()

    # message must be a string
    @staticmethod
    def __hash(message):
        return hashlib.sha256(bytes(message, "utf-8")).hexdigest()

    def receiving_msg(self, message, id):
        # the id is not needed for the check of MSG messages but the function requires it anyway
        if message["Source"] == id and self.first(message, "MSG", id):
            # if the tuple Source,SN is not in MsgSets then you add it with an empty list
            # that will be filled with next messages
            if (message["Source"], message["SequenceNumber"]) not in self.MsgSets:
                self.MsgSets.update({(message["Source"], message["SequenceNumber"]): [message["Message"]]})
            # if MsgSets contains already that tuple then you add message to the corresponding list
            else:
                self.MsgSets[(message["Source"], message["SequenceNumber"])].append(message["Message"])

            if self.selfid == 1:
                self.barrier.wait()
            else:
                self.update()
                self.faulty = math.floor((len(self.ids) - 1) / 3)

            # UNCOMMENT THIS SECTION TO BE MORE LOYAL TO THE SPECIFICATION
            # if ("ECHO", message["Source"], hashed_message, message["SequenceNumber"]) not in self.echo_counter:
                # if the counter is not initialized yet then it initializes the counter and assignes the value 1 to it
                # (because there is the message just received)
            #    self.echo_counter.update({("ECHO", message["Source"], hashed_message, message["SequenceNumber"]): 1})
            # else:
                # otherwise it increases its value
            #    self.echo_counter[("ECHO", message["Source"], hashed_message, message["SequenceNumber"])] += 1

            if ["ECHO", message["Source"], message["SequenceNumber"]] not in self.echos_sent:
                # It inserts the ECHO sent in the variable so that it is not sent again
                # It is done before the actual send because sending it to all other nodes is time-consuming,
                # so the process receives its own ECHO message before the insertion of the message
                self.echos_sent.append(["ECHO", message["Source"], message["SequenceNumber"]])
                hashed_message = self.__hash(message["Message"])
                packet = {"Flag": "ECHO", "Source": message["Source"], "Message": hashed_message, "SequenceNumber": message["SequenceNumber"]}
                for i in range(len(self.AL)):
                    self.AL[i].send(packet)

    def receiving_echo(self, echo, id):
        if self.first(echo, "ECHO", id):
            if ("ECHO", echo["Source"], echo["Message"], echo["SequenceNumber"]) not in self.echo_counter:
                # if the counter is not initialized yet then it initializes the counter and assignes the value 1 to it
                # (because there is the message just received)
                self.echo_counter.update({("ECHO", echo["Source"], echo["Message"], echo["SequenceNumber"]): 1})
            else:
                # otherwise it increases its value
                self.echo_counter[("ECHO", echo["Source"], echo["Message"], echo["SequenceNumber"])] += 1
            self.check(echo["Source"], echo["Message"], echo["SequenceNumber"])

    def receiving_acc(self, acc, id):
        if self.first(acc, "ACC", id):
            # in the self.acc_counter, storing the number of accs received is not enough,
            # but you have to store also the ids of the processes that sent them
            # in order to be able to send them a REQ message to get the message that has acc["Message"] as its hash
            # This is done because it may happen that a node did not receive the original message,
            # so it asks to f+1 nodes to send their messages to it (because f is the number of the faulty processes,
            # it is sure to get at least one answer from a correct process by asking it to f+1)

            if ("ACC", acc["Source"], acc["Message"], acc["SequenceNumber"]) not in self.acc_counter:
                # if the counter is not initialized yet then it initializes the counter
                # and stores the id of the one that sent the acc
                self.acc_counter.update({("ACC", acc["Source"], acc["Message"], acc["SequenceNumber"]): [id]})
            else:
                # otherwise it simply adds the id of the sender
                self.acc_counter[("ACC", acc["Source"], acc["Message"], acc["SequenceNumber"])].append(id)

            if len(self.acc_counter[("ACC", acc["Source"], acc["Message"], acc["SequenceNumber"])]) == self.faulty + 1:
                thereis = False
                if (acc["Source"], acc["SequenceNumber"]) in self.MsgSets:
                    msgs = self.MsgSets[(acc["Source"], acc["SequenceNumber"])]

                    for msg in msgs:
                        if self.__hash(msg) == acc["Message"]:
                            thereis = True
                if not thereis:
                    for i in range(len(self.AL)):
                        for link_id in self.acc_counter[("ACC", acc["Source"], acc["Message"], acc["SequenceNumber"])]:
                            if link_id == self.AL[i].get_id():
                                packet = {"Flag": "REQ", "Source": acc["Source"], "Message": acc["Message"],
                                          "SequenceNumber": acc["SequenceNumber"]}
                                self.AL[i].send(packet)
                                # it adds the current packet and the id of the receiver to keep track of them
                                # for the check that receiving_fwd will do
                                self.reqs_sent.append(["REQ", acc["Source"], acc["Message"], acc["SequenceNumber"], id])

            # This is a revised version of the code where it does not check the id of the sender
            # but the id of the source
            self.check(acc["Source"], acc["Message"], acc["SequenceNumber"])
            # This is the original version of the algorithm
            # self.check(id, acc["Message"], acc["SequenceNumber"])

    def receiving_req(self, req, id):
        if self.first(req, "REQ", id):
            thereis = False
            sel_msg = None
            for msg in self.MsgSets[(req["Source"], req["SequenceNumber"])]:
                if self.__hash(msg) == req["Message"]:
                    sel_msg = msg
                    thereis = True
            if thereis:
                for i in range(len(self.AL)):
                    if id == self.AL[i].get_id():
                        packet = {"Flag": "FWD", "Source": req["Source"], "Message": sel_msg,
                                  "SequenceNumber": req["SequenceNumber"]}
                        self.AL[i].send(packet)

    def receiving_fwd(self, fwd, id):
        if ["REQ", fwd["Source"], self.__hash(fwd["Message"]), fwd["SequenceNumber"], id] in self.reqs_sent and self.first(fwd, "FWD", id):
            # if the tuple Source,SN is not in MsgSets then you add it with an empty list
            # that will be filled with next messages
            if (fwd["Source"], fwd["SequenceNumber"]) not in self.MsgSets:
                self.MsgSets.update({[fwd["Source"], fwd["SequenceNumber"]]: [fwd["Message"]]})
            # if MsgSets contains already that tuple then you add message to the corresponding list
            else:
                self.MsgSets[(fwd["Source"], fwd["SequenceNumber"])].append(fwd["Message"])
            self.check(fwd["Source"], self.__hash(fwd["Message"]), fwd["SequenceNumber"])

    def check(self, source, hash_msg, sequence_number):
        # Ho assunto che ci possano essere messaggi contenuti in MsgSets che sono stati inviati da processi bizantini
        # e che, per qualche motivo, possano avere >= f + 1 riscontri (forse se il bizantino è proprio il mittente
        # originario, anche se andrebbe controllato in quel caso cosa succede all'algoritmo)
        # TODO check whether it is possible and what would happen if the sender is byzantine
        if (source, sequence_number) in self.MsgSets:
            for msg in self.MsgSets[(source, sequence_number)]:
                print(self.echo_counter, self.echos_rec, self.echos_sent)
                print(self.acc_counter, self.accs_rec, self.accs_sent)
                if self.__hash(msg) == hash_msg:

                    # the two ifs are merged inside only one because there is no action taken without one of them
                    if self.echo_counter[("ECHO", source, hash_msg, sequence_number)] >= self.faulty + 1 and ["ECHO", source, sequence_number] not in self.echos_sent:
                        # It inserts the ECHO sent in the variable so that it is not sent again
                        # It is done before the actual send because sending it to all other nodes is time-consuming,
                        # so the process receives its own ECHO message before the insertion of the message
                        self.echos_sent.append(["ECHO", source, sequence_number])
                        packet = {"Flag": "ECHO", "Source": source, "Message": hash_msg, "SequenceNumber": sequence_number}
                        self.update()
                        for i in range(len(self.AL)):
                            self.AL[i].send(packet)

                    elif self.echo_counter[("ECHO", source, hash_msg, sequence_number)] >= len(self.ips) - self.faulty and ["ACC", source, sequence_number] not in self.accs_sent:
                        print("Echos received: ", self.echos_rec)
                        print("-----ACC PHASE-----")
                        # It is done before the actual send because sending it to all other nodes is time-consuming,
                        # so the process receives its own ACC message before the insertion of the message
                        self.accs_sent.append(["ACC", source, sequence_number])
                        packet = {"Flag": "ACC", "Source": source, "Message": hash_msg, "SequenceNumber": sequence_number}
                        for i in range(len(self.AL)):
                            self.AL[i].send(packet)

                    # First condition is used in order not to get a KeyError
                    # Indeed, if the first condition is not satisfied, the other conditions won't be even evaluated
                    # It is not used before because the check function is called for the first time after receiving an ECHO
                    # TODO check if the above statement is confirmed even with byzantine nodes
                    elif ("ACC", source, hash_msg, sequence_number) in self.acc_counter and len(self.acc_counter[("ACC", source, hash_msg, sequence_number)]) >= self.faulty + 1 and ["ACC", source, sequence_number] not in self.accs_sent:
                        # Same as before
                        self.accs_sent.append(["ACC", source, sequence_number])
                        packet = {"Flag": "ACC", "Source": source, "Message": hash_msg, "SequenceNumber": sequence_number}
                        for i in range(len(self.AL)):
                            self.AL[i].send(packet)

                    # Same as before
                    elif ("ACC", source, hash_msg, sequence_number) in self.acc_counter and len(self.acc_counter[("ACC", source, hash_msg, sequence_number)]) >= len(self.ips) - self.faulty:
                        print("-----Message Delivered-----")
                        print("-----<", source, msg, sequence_number, ">-----")

    def first(self, message, flag, sender):
        if flag == "MSG":
            if ["MSG", message["Source"], message["SequenceNumber"]] not in self.msg:
                self.msg.append(["MSG", message["Source"], message["SequenceNumber"]])
                return True
            return False
        elif flag == "ECHO":
            if ["ECHO", message["Source"], message["SequenceNumber"], sender] not in self.echos_rec:
                self.echos_rec.append(["ECHO", message["Source"], message["SequenceNumber"], sender])
                return True
            return False
        elif flag == "ACC":
            if ["ACC", message["Source"], message["SequenceNumber"], sender] not in self.accs_rec:
                self.accs_rec.append(["ACC", message["Source"], message["SequenceNumber"], sender])
                return True
            return False
        elif flag == "REQ":
            if ["REQ", message["Source"], message["SequenceNumber"], sender] not in self.reqs_rec:
                self.reqs_rec.append(["REQ", message["Source"], message["SequenceNumber"], sender])
                return True
            return False
        elif flag == "FWD":
            if ["FWD", message["Source"], message["Message"], message["SequenceNumber"], sender] not in self.fwds_rec:
                self.fwds_rec.append(["FWD", message["Source"], message["Message"], message["SequenceNumber"], sender])
                return True
            return False
