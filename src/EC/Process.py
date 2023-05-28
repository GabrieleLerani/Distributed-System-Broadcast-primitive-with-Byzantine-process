import math
import hashlib
from EC.AuthenticatedLink import AuthenticatedLink
from EC.Evaluation import Evaluation
import threading
import logging
import EC.utils as utils
import time
import itertools


BROADCASTER_ID = 1
DROP_MSG_ID = 100  # specify the id of the process which drops message with flag MSG
DROP_ECHO_ID = 100  # specify the id of the process which drops message with flag ECHO


class Process:
    def __init__(self):
        self.ids = []
        self.ips = []
        self.selfip = 0
        self.selfid = 0
        self.AL = []
        self.h = 0  # sequence number of the message
        self.MsgSet = {}
        self.COUNTER = {}
        self.CodeSet = {}
        self.ReceivedMsg = []  # List instead of dictionary
        self.SentECHO = []  # List instead of dictionary
        self.RECEIVEDECHO = {}
        self.SentACC = []  # List instead of dictionary
        self.RECEIVEDACC = {}
        self.SENTREQ = {}
        self.RECEIVEDREQ = {}
        self.RECEIVEDFWD = {}
        self.faulty = 0
        self.fragments = []
        self.eval = Evaluation()
        self.delivered = False
        self.bit_echo = False
        self.k = 0  # message is split in k fragments, this value is used for MDS
        self.codeword = []

    def init_process(self):
        # start tracing memory usage
        self.eval.tracing_start()

        # get process ids
        self.init_process_ids()

        # set number of faulty process allowed by the protocol
        self.faulty = math.floor((len(self.ids) - 1) / 3)

        # set number k of MDS
        self.k = (
            self.faulty + 1
        )  # Number of data elements is n - 3f according to the theorem
        logging.debug("PROCESS: id list: %s,ip list %s", self.ids, self.ips)
        print("-----GATHERED ALL THE PEERS IPS AND IDS-----")
        print("-----STARTING SENDING OR RECEIVING MESSAGES-----")

    def init_process_ids(self):
        # read process identifier from file where each row is <id,ip>
        processes = utils.read_process_identifier()
        for pair in processes:
            self.ids.append(int(pair[0]))  # pair[0] --> ID
            self.ips.append(pair[1])  # pair[1] --> IPS

    def creation_links(self):
        self.selfip = utils.get_ip_of_interface()
        self.selfid = self.ids[self.ips.index(self.selfip)]
        self.barrier = threading.Barrier(parties=2)

        # start receiving side
        for i in range(0, len(self.ids)):
            self.AL.append(
                AuthenticatedLink(
                    self.selfid, self.selfip, self.ids[i], self.ips[i], self
                )
            )
            self.AL[i].receiver()

        # trigger key exchange for authenticated link so that processes can exchange authentic messages
        for i in range(0, len(self.ids)):
            self.AL[i].key_exchange()

    @staticmethod
    def __hash(message):
        return hashlib.sha256(bytes(str(message), "utf-8")).hexdigest()

    def process_receive(self, message):
        # receive messages from the underlying link
        match message.get("FLAG"):
            case "MSG":
                self.deliver_msg(message)

            case "ECHO":
                self.deliver_echo(message)

            case "ACC":
                self.deliver_acc(message)

            case "REQ":
                self.deliver_req(message)

            case "FWD":
                self.deliver_fwd(message)
            case _:
                logging.info("PROCESS:ERROR:Received a message of flag undefined")

    def broadcast(self, *args):
        message = ""
        size = 0
        if len(args) > 0:
            # Enter message you want to broadcast
            size = args[0]
            message = utils.generate_payload(size)
        else:
            message = str(input("Enter message: "))

        logging.info(
            "----- EVALUATION CHECKPOINT: broadcast start, time: %s -----",
            time.time() * 1000,
        )

        # get codeword from message m
        self.codeword = utils.encode(message, self.k, len(self.ids))

        # send message to all other along with the corresponding coded element
        for i in range(len(self.ids)):
            message_to_send = {
                "FLAG": "MSG",
                "FROM": str(self.selfid),
                "SOURCE": str(self.selfid),
                "HASH": self.__hash(message),
                "C": list(self.codeword[i]),
                "SEQUENCENUMBER": str(self.h),
            }

            self.AL[i].send(message_to_send)

        self.barrier.wait()

    def deliver_msg(self, msg):
        # MESSAGE{'FLAG':flag,'FROM':from,'S':s}
        # id == 1 checks that the delivery is computed with the sender s that by convention it's the first
        # s is meant for the broadcaster or for the source of the message it changes something?
        if self.selfid != DROP_MSG_ID:
            if (
                msg["FROM"] == msg["SOURCE"]
                and ["MSG", str(msg["SOURCE"]), str(msg["SEQUENCENUMBER"])]
                not in self.ReceivedMsg
            ):
                self.ReceivedMsg.append(
                    ["MSG", str(msg["SOURCE"]), str(msg["SEQUENCENUMBER"])]
                )

                if self.selfid == BROADCASTER_ID:
                    self.barrier.wait()

                logging.info(
                    "PROCESS: %d,%s --- Starting the ECHO part...",
                    self.selfid,
                    self.selfip,
                )

                src_hash_sn = (
                    str(msg["SOURCE"]) + str(msg["HASH"]) + str(msg["SEQUENCENUMBER"])
                )

                if src_hash_sn not in self.CodeSet.keys():
                    self.CodeSet[src_hash_sn] = []

                if (bytes(msg["C"])) not in self.CodeSet[src_hash_sn]:
                    self.CodeSet[src_hash_sn].append(bytes(msg["C"]))

                echo_s_hash_H = (
                    str("ECHO")
                    + str(msg["SOURCE"])
                    + str(msg["HASH"])
                    + str(msg["SEQUENCENUMBER"])
                )
                self.COUNTER.setdefault(echo_s_hash_H, 0)

                if [
                    "ECHO",
                    msg["SOURCE"],
                    msg["SEQUENCENUMBER"],
                ] not in self.SentECHO:
                    self.SentECHO.append(["ECHO", msg["SOURCE"], msg["SEQUENCENUMBER"]])

                    packet = {
                        "FLAG": "ECHO",
                        "FROM": str(self.selfid),
                        "SOURCE": str(msg["SOURCE"]),
                        "HASH": str(msg["HASH"]),
                        "C": msg["C"],
                        "SEQUENCENUMBER": str(msg["SEQUENCENUMBER"]),
                    }

                    for i in range(len(self.ids)):
                        self.AL[i].send(packet)

    def deliver_echo(self, msg):
        if self.selfid != DROP_ECHO_ID:
            self.bit_echo = True

            flag_src_sn = (
                str(msg["FLAG"]) + str(msg["SOURCE"]) + str(msg["SEQUENCENUMBER"])
            )
            if flag_src_sn not in self.RECEIVEDECHO.keys():
                self.RECEIVEDECHO[flag_src_sn] = []

            if msg["FROM"] not in self.RECEIVEDECHO[flag_src_sn]:
                self.RECEIVEDECHO[flag_src_sn].append(msg["FROM"])

                flag_src_hash_sn = (
                    str(msg["FLAG"])
                    + str(msg["SOURCE"])
                    + str(msg["HASH"])
                    + str(msg["SEQUENCENUMBER"])
                )
                # used to avoid key error, it sets a default value of 0
                self.COUNTER.setdefault(
                    flag_src_hash_sn,
                    0,
                )

                self.COUNTER[flag_src_hash_sn] += 1

                src_hash_sn = (
                    str(msg["SOURCE"]) + str(msg["HASH"]) + str(msg["SEQUENCENUMBER"])
                )
                # used not to generate the error
                if src_hash_sn not in self.CodeSet.keys():
                    self.CodeSet[src_hash_sn] = []

                if bytes(msg["C"]) not in self.CodeSet[src_hash_sn]:
                    self.CodeSet[src_hash_sn].append(bytes(msg["C"]))

                if (
                    self.COUNTER[
                        str(msg["FLAG"])
                        + str(msg["SOURCE"])
                        + str(msg["HASH"])
                        + str(msg["SEQUENCENUMBER"])
                    ]
                    >= self.faulty + 1
                ):
                    there_is = False
                    src_sn = str(msg["SOURCE"]) + str(msg["SEQUENCENUMBER"])

                    if src_sn not in self.MsgSet.keys():
                        self.MsgSet[src_sn] = []
                    for j in self.MsgSet[src_sn]:
                        if self.__hash(j) == str(msg["HASH"]):
                            there_is = True
                            break

                    if not there_is:
                        src_hash_from = (
                            str(msg["SOURCE"])
                            + str(msg["HASH"])
                            + str(msg["SEQUENCENUMBER"])
                        )

                        if src_hash_from not in self.CodeSet.keys():
                            self.CodeSet[src_hash_from] = []

                        subset = self.CodeSet[src_hash_from]

                        # get all subset of length f + 1 from code set
                        c = list(itertools.combinations(subset, self.faulty + 1))

                        # remove first elements because it's an empty list:[]
                        c.pop(0)

                        for l in c:
                            # decode m from the set of encoded element
                            m = utils.decode(l, self.k, len(self.ids))

                            hash_msg = self.__hash(m)

                            if msg["HASH"] == hash_msg:
                                self.MsgSet[
                                    str(msg["SOURCE"]) + str(msg["SEQUENCENUMBER"])
                                ].append(m)
                                break

                self.bit_echo = False

                self.check(msg["SOURCE"], msg["HASH"], msg["SEQUENCENUMBER"])
            self.bit_echo = False

    def deliver_acc(self, msg):
        flag_src_sn = str(msg["FLAG"]) + str(msg["SOURCE"]) + str(msg["SEQUENCENUMBER"])

        if flag_src_sn not in self.RECEIVEDACC.keys():
            self.RECEIVEDACC[flag_src_sn] = []

        if msg["FROM"] not in self.RECEIVEDACC[flag_src_sn]:
            self.RECEIVEDACC[flag_src_sn].append(msg["FROM"])

            # used to avoid key error, set default value of 0 for that key
            flag_src_hash_sn = (
                str(msg["FLAG"])
                + str(msg["SOURCE"])
                + str(msg["HASH"])
                + str(msg["SEQUENCENUMBER"])
            )

            self.COUNTER.setdefault(
                flag_src_hash_sn,
                0,
            )

            self.COUNTER[flag_src_hash_sn] += 1

            if self.COUNTER[flag_src_hash_sn] >= self.faulty + 1:
                there_is = False

                src_sn = str(msg["SOURCE"]) + str(msg["SEQUENCENUMBER"])

                if src_sn not in self.MsgSet.keys():
                    self.MsgSet[src_sn] = []

                while self.bit_echo:
                    pass

                for j in self.MsgSet[src_sn]:
                    if self.__hash(j) == str(msg["HASH"]):
                        there_is = True
                        break
                if not there_is:
                    packet = {
                        "FLAG": "REQ",
                        "SOURCE": str(msg["SOURCE"]),
                        "FROM": str(self.selfid),
                        "HASH": str(msg["HASH"]),
                        "SEQUENCENUMBER": str(msg["SEQUENCENUMBER"]),
                    }
                    for j in range(0, len(self.ids)):
                        req_src_hash_sn = (
                            "REQ"
                            + str(msg["SOURCE"])
                            + str(msg["HASH"])
                            + str(msg["SEQUENCENUMBER"])
                        )

                        if req_src_hash_sn not in self.SENTREQ.keys():
                            self.SENTREQ[req_src_hash_sn] = []
                        if str(j + 1) not in self.SENTREQ[req_src_hash_sn]:
                            self.SENTREQ[req_src_hash_sn].append(str(j + 1))
                            self.AL[j].send(packet)

            # The following row should be wrong in the original algorithm
            # self.check(msg["FROM"], msg["HASH"], msg["SEQUENCENUMBER"])
            self.check(msg["SOURCE"], msg["HASH"], msg["SEQUENCENUMBER"])

    def deliver_req(self, msg):
        flag_src_sn = str(msg["FLAG"]) + str(msg["SOURCE"]) + str(msg["SEQUENCENUMBER"])

        if flag_src_sn not in self.RECEIVEDREQ.keys():
            self.RECEIVEDREQ[flag_src_sn] = []

        if msg["FROM"] not in self.RECEIVEDREQ[flag_src_sn]:
            self.RECEIVEDREQ[flag_src_sn].append(msg["FROM"])
            there_is = False
            message = ""

            src_sn = str(msg["SOURCE"]) + str(msg["SEQUENCENUMBER"])
            if src_sn not in self.MsgSet.keys():
                self.MsgSet[src_sn] = []
            for j in self.MsgSet[src_sn]:
                if self.__hash(j) == str(msg["HASH"]):
                    there_is = True
                    message = j
                    break
            if there_is:
                packet = {
                    "FLAG": "FWD",
                    "FROM": str(self.selfid),
                    "SOURCE": str(msg["SOURCE"]),
                    "MESSAGE": message,
                    "SEQUENCENUMBER": msg["SEQUENCENUMBER"],
                }
                self.AL[int(msg["FROM"]) - 1].send(packet)

    def deliver_fwd(self, msg):
        hash_msg = self.__hash(msg["MESSAGE"])
        flag_src_hash_msg = (
            "REQ" + str(msg["SOURCE"]) + str(hash_msg) + str(msg["SEQUENCENUMBER"])
        )

        if flag_src_hash_msg not in self.SENTREQ.keys():
            self.SENTREQ[flag_src_hash_msg] = []
        # msg['FROM'] is the real id of the process

        if msg["FROM"] in self.SENTREQ[flag_src_hash_msg]:
            flag_src_msg_sn = (
                str(msg["FLAG"])
                + str(msg["SOURCE"])
                + str(msg["MESSAGE"])
                + str(msg["SEQUENCENUMBER"])
            )

            if flag_src_msg_sn not in self.RECEIVEDFWD.keys():
                self.RECEIVEDFWD[flag_src_msg_sn] = []
            if msg["FROM"] not in self.RECEIVEDFWD[flag_src_msg_sn]:
                self.RECEIVEDFWD[flag_src_msg_sn].append(str(msg["FROM"]))

                self.MsgSet[str(msg["SOURCE"]) + str(msg["SEQUENCENUMBER"])].append(
                    msg["MESSAGE"]
                )

                self.check(msg["SOURCE"], hash_msg, msg["SEQUENCENUMBER"])

    def check(self, s, hash_msg, sn):
        there_is = False
        message = ""

        if str(s) + str(sn) not in self.MsgSet.keys():
            self.MsgSet[str(s) + str(sn)] = []
        for j in self.MsgSet[str(s) + str(sn)]:
            if self.__hash(j) == str(hash_msg):
                there_is = True
                message = j
                break
        if there_is:
            if (
                self.COUNTER["ECHO" + str(s) + str(hash_msg) + str(sn)]
                >= self.faulty + 1
                and ["ECHO", str(s), str(sn)] not in self.SentECHO
            ):
                self.SentECHO.append(["ECHO", str(s), str(sn)])

                # Generate codeword for message
                temp_codeword = utils.encode(message, self.k, len(self.ids))

                # send coded element within an ECHO message to all processes
                for i in range(len(self.ids)):
                    coded_element = list(temp_codeword[i])

                    packet = {
                        "FLAG": "ECHO",
                        "FROM": str(self.selfid),
                        "SOURCE": str(s),
                        "HASH": str(hash_msg),
                        "C": coded_element,
                        "SEQUENCENUMBER": str(sn),
                    }

                    self.AL[i].send(packet)

            elif (
                self.COUNTER["ECHO" + str(s) + str(hash_msg) + str(sn)]
                >= len(self.ids) - self.faulty
                and ["ACC", str(s), str(sn)] not in self.SentACC
            ):
                self.SentACC.append(["ACC", s, sn])

                for i in range(len(self.ids)):
                    packet = {
                        "FLAG": "ACC",
                        "FROM": str(self.selfid),
                        "SOURCE": str(s),
                        "HASH": hash_msg,
                        "SEQUENCENUMBER": str(sn),
                    }
                    self.AL[i].send(packet)

            elif (
                "ACC" + str(s) + str(hash_msg) + str(sn) in self.COUNTER.keys()
                and self.COUNTER["ACC" + str(s) + str(hash_msg) + str(sn)]
                >= self.faulty + 1
                and ["ACC", str(s), str(sn)] not in self.SentACC
            ):
                self.SentACC.append(["ACC", s, sn])

                for i in range(len(self.ids)):
                    packet = {
                        "FLAG": "ACC",
                        "FROM": str(self.selfid),
                        "SOURCE": str(s),
                        "HASH": hash_msg,
                        "SEQUENCENUMBER": str(sn),
                    }
                    self.AL[i].send(packet)

            elif (
                "ACC" + str(s) + str(hash_msg) + str(sn) in self.COUNTER.keys()
                and self.COUNTER["ACC" + str(s) + str(hash_msg) + str(sn)]
                >= len(self.ids) - self.faulty
            ):
                msg = {"SOURCE": s, "MESSAGE": message, "SEQUENCENUMBER": sn}

                if not self.delivered:
                    self.delivered = True
                    self.__deliver(msg["MESSAGE"])

                logging.info("BYTES SENT: %d", self.__get_bytes_sent() / 1024)

    def __deliver(self, msg):
        # delivering the final message that is a dictionary
        print("-----MESSAGE DELIVERED: ", msg)

        peak = self.eval.tracing_mem()
        logging.info(
            "-----MESSAGE DELIVERED, time: %s, size: %s",
            time.time() * 1000,
            peak,
        )

    def __get_bytes_sent(self):
        sent = 0
        for i in range(0, len(self.AL)):
            sent += self.AL[i].bytes_sent
        return sent
