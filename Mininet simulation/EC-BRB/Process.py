import math
import hashlib
import AuthenticatedLink
import threading
import logging
import utils
import Evaluation
import time
import itertools
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from base64 import b64encode


BROADCASTER_ID = 1


class Process:
    def __init__(self):
        self.ids = []
        self.ips = []
        self.selfip = 0
        self.selfid = 0
        self.AL = []
        self.h = 0  # sequence number of the message
        self.ENC_INF = {}
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
        self.eval = Evaluation.Evaluation()
        self.delivered = False
        self.bit_echo = False

    def init_process(self):
        self.eval.tracing_start()
        self.init_process_ids()
        self.faulty = math.floor((len(self.ids) - 1) / 3)
        logging.debug("PROCESS: id list: %s,ip list %s", self.ids, self.ips)
        print("-----GATHERED ALL THE PEERS IPS AND IDS-----")
        print("-----STARTING SENDING OR RECEIVING MESSAGES-----")

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

        for i in range(0, len(self.ids)):
            self.AL[i].key_exchange()

    # message must be a string
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
            case "ENC_INF":
                self.deliver_enc_inf(message)
            case _:
                logging.info("PROCESS:ERROR:Received a message of flag undefined")

    def encrypt(self, msg, sid, sn):
        # Compute the hash of the message
        hash_msg = self.__hash(msg)

        # Preparation of the Shamir algorithm
        key = get_random_bytes(16)

        shares = Shamir.split(self.faulty + 1, len(self.ips), key)

        # write shares on logging
        for idx, share in shares:
            logging.info("PROCESS:Index #%d: %s" % (idx, hexlify(share)))

        # Creation of the n fragments
        cipher = AES.new(key, AES.MODE_EAX)
        ct, tag = cipher.encrypt(msg.encode()), cipher.digest()

        enc_inf_key = str(sid) + str(hash_msg) + str(sn)

        self.ENC_INF[enc_inf_key] = [cipher.nonce, tag, ct]

        # encode enf inf with latin to allow json dump
        packet = {"FLAG": "ENC_INF", enc_inf_key: []}
        temp_ENC = [cipher.nonce, tag, ct]
        for i in range(len(temp_ENC)):
            packet[enc_inf_key].append(list(temp_ENC[i]))

        # send nonce tag and ct to other
        for i in range(len(self.ids)):
            self.AL[i].send(packet)

        emsg = b64encode(cipher.nonce + tag + ct)
        logging.info("PROCESS:%s", emsg)

        if enc_inf_key not in self.CodeSet.keys():
            self.CodeSet[enc_inf_key] = []

        for i in range(0, len(self.ids)):
            self.fragments.append(shares[i])

    def decrypt(self, C, s, h, H):
        # create a 4 data block with 2 parity block code generator

        C = utils.list_to_tuple(C)

        # C must be a list of tuples like (index,share)
        key = Shamir.combine(C)

        # TODO process which is not the sender has self.ENC_INF empty
        nonce, tag = self.ENC_INF[str(s) + str(H) + str(h)][:2]
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        try:
            result = cipher.decrypt(self.ENC_INF[str(s) + str(H) + str(h)][2])
            cipher.verify(tag)

            return result
        except ValueError:
            print("The shares were incorrect")

    def broadcast(self, message):
        logging.info(
            "----- EVALUATION CHECKPOINT: broadcast start, time: %s -----",
            time.time() * 1000,
        )
        # TODO

        # self.h = self.h+1 # incrementing sequence number
        self.h = self.selfid
        self.encrypt(
            message, self.selfid, self.h
        )  # creating coded elements and inserting them into self.CodeSet

        for i in range(len(self.ids)):
            number = self.fragments[i][0]

            # convert the byte sequence of each fragment to a list so to ease
            # sending process and encoding
            share = list(self.fragments[i][1])

            message_to_send = {
                "FLAG": "MSG",
                "FROM": str(self.selfid),
                "SOURCE": str(self.selfid),
                "HASH": self.__hash(message),
                "C": [number, share],
                "SEQUENCENUMBER": str(self.h),
            }

            self.AL[i].send(message_to_send)

        self.barrier.wait()

    def deliver_msg(self, msg):
        # MESSAGE{'FLAG':flag,'FROM':from,'S':s}
        # id == 1 checks that the delivery is computed with the sender s that by convention it's the first
        # s is meant for the broadcaster or for the source of the message it changes something?

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
                "PROCESS: %d,%s --- Starting the ECHO part...", self.selfid, self.selfip
            )

            src_hash_sn = (
                str(msg["SOURCE"]) + str(msg["HASH"]) + str(msg["SEQUENCENUMBER"])
            )

            if src_hash_sn not in self.CodeSet.keys():
                self.CodeSet[src_hash_sn] = []

            # TODO FOR ENCODING
            if (msg["C"][0], bytes(msg["C"][1])) not in self.CodeSet[src_hash_sn]:
                self.CodeSet[src_hash_sn].append((msg["C"][0], bytes(msg["C"][1])))

            echo_s_hash_H = (
                str("ECHO")
                + str(msg["SOURCE"])
                + str(msg["HASH"])
                + str(msg["SEQUENCENUMBER"])
            )
            self.COUNTER.setdefault(echo_s_hash_H, 0)

            if ["ECHO", msg["SOURCE"], msg["SEQUENCENUMBER"]] not in self.SentECHO:
                self.SentECHO.append(["ECHO", msg["SOURCE"], msg["SEQUENCENUMBER"]])

                number = msg["C"][0]
                share = msg["C"][1]

                packet = {
                    "FLAG": "ECHO",
                    "FROM": str(self.selfid),
                    "SOURCE": str(msg["SOURCE"]),
                    "HASH": str(msg["HASH"]),
                    "C": [number, share],
                    "SEQUENCENUMBER": str(msg["SEQUENCENUMBER"]),
                }

                for i in range(len(self.ids)):
                    self.AL[i].send(packet)

    def deliver_echo(self, msg):
        self.bit_echo = True

        flag_src_sn = str(msg["FLAG"]) + str(msg["SOURCE"]) + str(msg["SEQUENCENUMBER"])
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

            print("----", msg["C"][1])
            if (msg["C"][0], bytes(msg["C"][1])) not in self.CodeSet[src_hash_sn]:
                self.CodeSet[src_hash_sn].append((msg["C"][0], bytes(msg["C"][1])))

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
                    # checking condition and why j
                    # src_hash_from = (
                    #     str(msg["SOURCE"]) + str(msg["HASH"]) + str(msg["FROM"])
                    # )
                    src_hash_from = (
                        str(msg["SOURCE"])
                        + str(msg["HASH"])
                        + str(msg["SEQUENCENUMBER"])
                    )

                    if src_hash_from not in self.CodeSet.keys():
                        self.CodeSet[src_hash_from] = []

                    subset = self.CodeSet[src_hash_from]

                    c = self.get_powerset(subset)
                    # c = list(itertools.combinations(subset, self.faulty + 1))

                    for l in c:
                        if len(l) == self.faulty + 1:  # and not utils.has_duplicate(l):
                            m = self.decrypt(
                                l, msg["SOURCE"], msg["SEQUENCENUMBER"], msg["HASH"]
                            ).decode(
                                "utf-8"
                            )  # TODO checking if passing a set coherent with decrypt function

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
                            # j + 1 is used both above and below because it is the real id of another process
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

                # TODO Non so se questa parte sia utile
                # if str('FWD') + str(msg['S']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER']) not in self.SENTFWD.keys():
                #    self.SENTFWD[str('REQ') + str(msg['S']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])] = []
                # self.SENTFWD['REQ' + str(message['S']) + str(msg['HASH']) + str(msg['SEQUENCENUMBER'])].append(str(msg['FROM']))

    def deliver_fwd(self, msg):
        hash_msg = self.__hash(msg["MESSAGE"])
        flag_src_hash_msg = (
            str(msg["FLAG"])
            + str(msg["SOURCE"])
            + str(hash_msg)
            + str(msg["SEQUENCENUMBER"])
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

                number = 0
                share = ""
                for elem in self.CodeSet[str(s) + str(hash_msg) + str(sn)]:
                    if elem[0] == self.selfid:
                        number = elem[0]
                        # share = elem[1].decode("latin-1")
                        share = list(elem[1])
                        break

                for i in range(len(self.ids)):
                    packet = {
                        "FLAG": "ECHO",
                        "FROM": str(self.selfid),
                        "SOURCE": str(s),
                        "HASH": str(hash_msg),
                        "C": [number, share],
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

            # TODO
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

    def deliver_enc_inf(self, msg):
        # decode message
        msg.pop("FLAG", None)
        dict_key = list(msg.keys())[0]

        for i in range(len(msg[dict_key])):
            # msg[dict_key][i] = msg[dict_key][i].encode("latin-1")
            msg[dict_key][i] = bytes(msg[dict_key][i])

        self.ENC_INF[dict_key] = msg[dict_key]

    def __deliver(self, msg):
        # delivering the final message that is a dictionary
        print("-----MESSAGE DELIVERED: ", msg)
        peak = self.eval.tracing_mem()
        logging.info(
            "-----MESSAGE DELIVERED, time: %s, size: %s",
            time.time() * 1000,
            peak,
        )

    def get_powerset(self, some_list):
        if len(some_list) == 0:
            return [[]]

        subsets = []
        first_element = some_list[0]
        remaining_list = some_list[1:]
        # Strategy: get all the subsets of remaining_list. For each
        # of those subsets, a full subset list will contain both
        # the original subset as well as a version of the subset
        # that contains first_element
        for partial_subset in self.get_powerset(remaining_list):
            subsets.append(partial_subset)
            subsets.append(partial_subset[:] + [first_element])

        return subsets
