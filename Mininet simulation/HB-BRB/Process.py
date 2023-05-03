import hashlib
import AuthenticatedLink
import threading
import logging
import math
import utils
import time
import Evaluation
import os


SERVER_ID = "192.168.1.41"
SERVER_PORT = 5000

RCV_BUFFER_SIZE = 4096
BREAK_TIME = 0.1

BROADCAST_ID = 1


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
        self.echo_counter = {} # counter of echos of a specific message received
        self.acc_counter = {}
        self.eval = Evaluation.Evaluation()
        self.delivered = False

    def init_process(self):
       
        self.eval.tracing_start()
        self.init_process_ids()
        self.faulty = math.floor((len(self.ids) - 1) / 3)
        logging.debug("PROCESS: id list: %s,ip list %s", self.ids, self.ips)
        print("-----GATHERED ALL THE PEERS IPS AND IDS-----")
        print("-----STARTING SENDING OR RECEIVING MESSAGES-----")
        print(f"{os.getpid()}")

    def init_process_ids(self):
        processes = utils.read_process_identifier()
        for pair in processes:
            self.ids.append(int(pair[0]))  # pair[0] --> ID
            self.ips.append(pair[1])  # pair[1] --> IPS

    def creation_links(self):
        self.selfip = utils.get_ip_of_interface()
        self.selfid = self.ids[self.ips.index(self.selfip)]
        self.barrier = threading.Barrier(parties=2)
        for i in range(0, len(self.ids)):
            self.AL.append(
                AuthenticatedLink.AuthenticatedLink(
                    self.selfid, self.selfip, self.ids[i], self.ips[i], self
                )
            )
            self.AL[i].receiver()
        
        # this is a real key exchange but is cpu consuming due to connection refused error
        # because the processes are not initialized at the same time and the receiving sockets ar not
        # perfectly synchronized
        for i in range(0, len(self.ids)):
            self.AL[i].key_exchange()


        # to ease simulation process reads symmetric key from file
        


    

    def broadcast(self, message):
        
        logging.info(
            "----- EVALUATION CHECKPOINT: broadcast start, time: %s -----",
            time.time() * 1000,
        )

        packet = {
            "Flag": "MSG",
            "Source": self.selfid,
            "Message": message,
            "SequenceNumber": self.h,
        }

        for i in range(len(self.AL)):
            self.AL[i].send(packet)
        self.barrier.wait()

    # message must be a string
    @staticmethod
    def __hash(message):
        return hashlib.sha256(bytes(message, "utf-8")).hexdigest()

    def receiving_msg(self, message, id):
        # the id is not needed for the check of MSG messages but the function requires it anyway
        if message["Source"] == BROADCAST_ID and self.first(message, "MSG", id):
            if (message["Source"], message["SequenceNumber"]) not in self.MsgSets:
                self.MsgSets.update(
                    {
                        (message["Source"], message["SequenceNumber"]): [
                            message["Message"]
                        ]
                    }
                )
            # if MsgSets contains already that tuple then you add message to the corresponding list
            else:
                self.MsgSets[(message["Source"], message["SequenceNumber"])].append(
                    message["Message"]
                )

            if self.selfid == 1:
                self.barrier.wait()
            else:
                
                self.faulty = math.floor((len(self.ids) - 1) / 3)

            # UNCOMMENT THIS SECTION TO BE MORE LOYAL TO THE SPECIFICATION
            # if ("ECHO", message["Source"], hashed_message, message["SequenceNumber"]) not in self.echo_counter:
            # if the counter is not initialized yet then it initializes the counter and assignes the value 1 to it
            # (because there is the message just received)
            #    self.echo_counter.update({("ECHO", message["Source"], hashed_message, message["SequenceNumber"]): 1})
            # else:
            # otherwise it increases its value
            #    self.echo_counter[("ECHO", message["Source"], hashed_message, message["SequenceNumber"])] += 1

            if [
                "ECHO",
                message["Source"],
                message["SequenceNumber"],
            ] not in self.echos_sent:
                # It inserts the ECHO sent in the variable so that it is not sent again
                # It is done before the actual send because sending it to all other nodes is time-consuming,
                # so the process receives its own ECHO message before the insertion of the message
                self.echos_sent.append(
                    ["ECHO", message["Source"], message["SequenceNumber"]]
                )
                hashed_message = self.__hash(message["Message"])

                
                packet = {}
                # TODO used to send byzantine message
                if self.selfid == 10:
                    byz_mess = "byz mess"

                    packet = {
                        "Flag": "ECHO",
                        "Source": message["Source"],
                        "Message": byz_mess,
                        "SequenceNumber": message["SequenceNumber"],
                    }

                else:
                    packet = {
                        "Flag": "ECHO",
                        "Source": message["Source"],
                        "Message": hashed_message,
                        "SequenceNumber": message["SequenceNumber"],
                    }

                for i in range(len(self.AL)):
                    self.AL[i].send(packet)

    def receiving_echo(self, echo, id):
        if self.first(echo, "ECHO", id):
            # Used because there can happen that a process receives self.faulty + 1 ACC messages before
            # receiving the MSG message and this leads to an error when it tries to retrieve that message from MsgSets

            if (
                "ECHO",
                echo["Source"],
                echo["Message"],
                echo["SequenceNumber"],
            ) not in self.echo_counter:
                # if the counter is not initialized yet then it initializes the counter and assignes the value 1 to it
                # (because there is the message just received)
                self.echo_counter.update(
                    {
                        (
                            "ECHO",
                            echo["Source"],
                            echo["Message"],
                            echo["SequenceNumber"],
                        ): 1
                    }
                )
            else:
                # otherwise it increases its value
                self.echo_counter[
                    ("ECHO", echo["Source"], echo["Message"], echo["SequenceNumber"])
                ] += 1
            self.check(echo["Source"], echo["Message"], echo["SequenceNumber"])

    def receiving_acc(self, acc, id):
        if self.first(acc, "ACC", id):
            # in the self.acc_counter, storing the number of accs received is not enough,
            # but you have to store also the ids of the processes that sent them
            # in order to be able to send them a REQ message to get the message that has acc["Message"] as its hash
            # This is done because it may happen that a node did not receive the original message,
            # so it asks to f+1 nodes to send their messages to it (because f is the number of the faulty processes,
            # it is sure to get at least one answer from a correct process by asking it to f+1)

            if (
                "ACC",
                acc["Source"],
                acc["Message"],
                acc["SequenceNumber"],
            ) not in self.acc_counter:
                # if the counter is not initialized yet then it initializes the counter
                # and stores the id of the one that sent the acc
                self.acc_counter.update(
                    {
                        ("ACC", acc["Source"], acc["Message"], acc["SequenceNumber"]): [
                            id
                        ]
                    }
                )
            else:
                # otherwise it simply adds the id of the sender
                self.acc_counter[
                    ("ACC", acc["Source"], acc["Message"], acc["SequenceNumber"])
                ].append(id)

            if (
                len(
                    self.acc_counter[
                        ("ACC", acc["Source"], acc["Message"], acc["SequenceNumber"])
                    ]
                )
                == self.faulty + 1
            ):
                # The next line is the reason why the class __add_to_msgsets is called also by receiving_echo and receiving_acc

                thereis = False
                if (acc["Source"], acc["SequenceNumber"]) in self.MsgSets:
                    msgs = self.MsgSets[(acc["Source"], acc["SequenceNumber"])]

                    for msg in msgs:
                        if self.__hash(msg) == acc["Message"]:
                            thereis = True
                if not thereis:
                    for i in range(len(self.AL)):
                        for link_id in self.acc_counter[
                            (
                                "ACC",
                                acc["Source"],
                                acc["Message"],
                                acc["SequenceNumber"],
                            )
                        ]:
                            if link_id == self.AL[i].get_id():
                                packet = {
                                    "Flag": "REQ",
                                    "Source": acc["Source"],
                                    "Message": acc["Message"],
                                    "SequenceNumber": acc["SequenceNumber"],
                                }
                                self.AL[i].send(packet)
                                # it adds the current packet and the id of the receiver to keep track of them
                                # for the check that receiving_fwd will do
                                self.reqs_sent.append(
                                    [
                                        "REQ",
                                        acc["Source"],
                                        acc["Message"],
                                        acc["SequenceNumber"],
                                        id,
                                    ]
                                )

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
                        packet = {
                            "Flag": "FWD",
                            "Source": req["Source"],
                            "Message": sel_msg,
                            "SequenceNumber": req["SequenceNumber"],
                        }
                        self.AL[i].send(packet)

    def receiving_fwd(self, fwd, id):
        if [
            "REQ",
            fwd["Source"],
            self.__hash(fwd["Message"]),
            fwd["SequenceNumber"],
            id,
        ] in self.reqs_sent and self.first(fwd, "FWD", id):
            # if the tuple Source,SN is not in MsgSets then you add it with an empty list
            # that will be filled with next messages
            if (fwd["Source"], fwd["SequenceNumber"]) not in self.MsgSets:
                self.MsgSets.update(
                    {[fwd["Source"], fwd["SequenceNumber"]]: [fwd["Message"]]}
                )
            # if MsgSets contains already that tuple then you add message to the corresponding list
            else:
                self.MsgSets[(fwd["Source"], fwd["SequenceNumber"])].append(
                    fwd["Message"]
                )
            self.check(
                fwd["Source"], self.__hash(fwd["Message"]), fwd["SequenceNumber"]
            )

    def check(self, source, hash_msg, sequence_number):
        # Ho assunto che ci possano essere messaggi contenuti in MsgSets che sono stati inviati da processi bizantini
        # e che, per qualche motivo, possano avere >= f + 1 riscontri (forse se il bizantino è proprio il mittente
        # originario, anche se andrebbe controllato in quel caso cosa succede all'algoritmo)
        # TODO check whether it is possible and what would happen if the sender is byzantine
        if (source, sequence_number) in self.MsgSets:
            for msg in self.MsgSets[(source, sequence_number)]:
                logging.info(
                    "ECHOS COUNTER: %s, ECHOS RECEIVED:%s ECHOS SENT: %s",
                    self.echo_counter,
                    self.echos_rec,
                    self.echos_sent,
                    
                )
                logging.info("MSG SET %s",self.MsgSets)

                logging.info(
                    "ACC COUNTER: %s, ACC RECEIVED:%s ACC SENT: %s",
                    self.acc_counter,
                    self.accs_rec,
                    self.accs_sent,
                )

                if self.__hash(msg) == hash_msg:
                    # the two ifs are merged inside only one because there is no action taken without one of them
                    if (
                        self.echo_counter[("ECHO", source, hash_msg, sequence_number)]
                        >= self.faulty + 1
                        and ["ECHO", source, sequence_number] not in self.echos_sent
                    ):
                        # It inserts the ECHO sent in the variable so that it is not sent again
                        # It is done before the actual send because sending it to all other nodes is time-consuming,
                        # so the process receives its own ECHO message before the insertion of the message
                        self.echos_sent.append(["ECHO", source, sequence_number])
                        packet = {
                            "Flag": "ECHO",
                            "Source": source,
                            "Message": hash_msg,
                            "SequenceNumber": sequence_number,
                        }
                        # self.update()
                        for i in range(len(self.AL)):
                            self.AL[i].send(packet)

                    elif (
                        self.echo_counter[("ECHO", source, hash_msg, sequence_number)]
                        >= len(self.ips) - self.faulty
                        and ["ACC", source, sequence_number] not in self.accs_sent
                    ):
                        logging.info("Echos received: %s", self.echos_rec)
                        logging.info("-----ACC PHASE-----")

                        # It is done before the actual send because sending it to all other nodes is time-consuming,
                        # so the process receives its own ACC message before the insertion of the message
                        self.accs_sent.append(["ACC", source, sequence_number])
                        packet = {
                            "Flag": "ACC",
                            "Source": source,
                            "Message": hash_msg,
                            "SequenceNumber": sequence_number,
                        }
                        for i in range(len(self.AL)):
                            self.AL[i].send(packet)

                    # First condition is used in order not to get a KeyError
                    # Indeed, if the first condition is not satisfied, the other conditions won't be even evaluated
                    # It is not used before because the check function is called for the first time after receiving an ECHO
                    # TODO check if the above statement is confirmed even with byzantine nodes
                    elif (
                        ("ACC", source, hash_msg, sequence_number) in self.acc_counter
                        and len(
                            self.acc_counter[("ACC", source, hash_msg, sequence_number)]
                        )
                        >= self.faulty + 1
                        and ["ACC", source, sequence_number] not in self.accs_sent
                    ):
                        # Same as before
                        self.accs_sent.append(["ACC", source, sequence_number])
                        packet = {
                            "Flag": "ACC",
                            "Source": source,
                            "Message": hash_msg,
                            "SequenceNumber": sequence_number,
                        }
                        for i in range(len(self.AL)):
                            self.AL[i].send(packet)

                    # Same as before
                    elif (
                        "ACC",
                        source,
                        hash_msg,
                        sequence_number,
                    ) in self.acc_counter and len(
                        self.acc_counter[("ACC", source, hash_msg, sequence_number)]
                    ) >= len(
                        self.ips
                    ) - self.faulty:
                        
                        if not self.delivered:
                            
                            self.delivered = True

                            print(
                                f"-----Message Delivered: {msg}-----",
                            )

                            peak = self.eval.tracing_mem()
                            logging.info(
                                "-----MESSAGE DELIVERED, time: %s, size: %s",
                                time.time() * 1000,
                                peak,
                            )



                            logging.info(
                                "----- <%s,%s,%d> -----", source, msg, sequence_number
                            )



    def first(self, message, flag, sender):
        if flag == "MSG":
            if ["MSG", message["Source"], message["SequenceNumber"]] not in self.msg:
                self.msg.append(["MSG", message["Source"], message["SequenceNumber"]])
                return True
            return False
        elif flag == "ECHO":
            if [
                "ECHO",
                message["Source"],
                message["SequenceNumber"],
                sender,
            ] not in self.echos_rec:
                self.echos_rec.append(
                    ["ECHO", message["Source"], message["SequenceNumber"], sender]
                )
                return True
            return False
        elif flag == "ACC":
            if [
                "ACC",
                message["Source"],
                message["SequenceNumber"],
                sender,
            ] not in self.accs_rec:
                self.accs_rec.append(
                    ["ACC", message["Source"], message["SequenceNumber"], sender]
                )
                return True
            return False
        elif flag == "REQ":
            if [
                "REQ",
                message["Source"],
                message["SequenceNumber"],
                sender,
            ] not in self.reqs_rec:
                self.reqs_rec.append(
                    ["REQ", message["Source"], message["SequenceNumber"], sender]
                )
                return True
            return False
        elif flag == "FWD":
            if [
                "FWD",
                message["Source"],
                message["Message"],
                message["SequenceNumber"],
                sender,
            ] not in self.fwds_rec:
                self.fwds_rec.append(
                    [
                        "FWD",
                        message["Source"],
                        message["Message"],
                        message["SequenceNumber"],
                        sender,
                    ]
                )
                return True
            return False
