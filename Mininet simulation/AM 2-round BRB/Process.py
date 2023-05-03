import math
import Link
import utils
import socket
from threading import Thread
import json
import time
import logging
from sys import platform
from hashlib import sha512
import Authenticated_Link
import Evaluation


KDS_IP = "10.0.0.1"
KDS_PORT = 8080

RCV_BUFFER_SIZE = 8192
BREAK_TIME = 0.1

BROADCASTER_ID = 1

PLACEHOLDER = "vote_msg"


class Process:
    def __init__(self):
        self.ids = []
        self.ips = []
        self.checked = {}
        self.signed_vote_messages = []
        self.sip = 0
        self.sid = 0
        self.L = []
        self.AL = []
        self.start = 0
        self.key_gen = False
        self.keyPair = {}
        self.public_keys = {}
        self.delivered = False
        self.counter_signed_mess = {}
        self.faulty = 0  # f<N/3 condition to protocol correctness
        self.eval = Evaluation.Evaluation()

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
        # binding my information

        # checking os
        self.sip = utils.get_ip_of_interface()
        self.sid = self.ids[self.ips.index(self.sip)]

        # creating links
        for i in range(0, len(self.ids)):
            # init links
            self.L.append(
                Link.Link(
                    self.sid,
                    self.sip,
                    self.ids[i],
                    self.ips[i],
                    self,
                )
            )
            # setting up links
            self.L[i].build_Link_r()
            self.L[i].build_Link_s()

        if self.sid == BROADCASTER_ID:
            for i in range(0, len(self.ids)):
                self.AL.append(
                    Authenticated_Link.AuthenticatedLink(
                        self.sid, self.sip, self.ids[i], self.ips[i], self
                    )
                )

        else:
            self.AL.append(
                Authenticated_Link.AuthenticatedLink(
                    self.sid, self.sip, self.ids[0], self.ips[0], self
                )
            )
        self.AL[0].receiver()

        # Start key exchange
        for i in range(len(self.ids)):
            self.AL[i].key_exchange()

    def broadcast(self, message):
        # broadcasting messages to all processes

        msg = {}
        msg["TYPE"] = 0
        msg["FLAG"] = "PROPOSE"
        msg["MSG"] = message
        msg["FROM"] = BROADCASTER_ID

        for j in range(0, len(self.ids)):
            self.AL[j].send(msg)
            # self.barrier.wait()  # to remain consistent
        logging.info("PROCESS:Message:%s,broadcasted successfully", message)

    def process_receive(self, message):
        # receive messages from the underlying pppl
        match message.get("TYPE"):
            case 0:
                if (
                    message.get("FROM") == BROADCASTER_ID
                    and message.get("FLAG") == "PROPOSE"
                ):
                    # self.broadcast(msg)
                    msg = {}
                    msg["FLAG"] = "VOTE"
                    msg["MSG"] = message.get("MSG")
                    msg["SIGN"] = self.make_signature(msg.get("FLAG") + msg.get("MSG"))
                    msg["TYPE"] = 1
                    msg["FROM"] = self.sid

                    for j in range(0, len(self.ids)):
                        self.L[j].link_send(msg)
                    logging.info(
                        "PROCESS:Vote message:%s,broadcasted successfully", msg
                    )

            case 1:
                # key used to reduce redundancy
                key_to_check = (
                    message.get("FLAG"),
                    message.get("MSG"),
                    message.get("SIGN"),
                    message.get("FROM"),
                )

                # we check whether a message sign has already been checked
                if message.get("FLAG") == "VOTE":
                    if key_to_check not in self.checked.keys():
                        print("Checking signature")
                        self.checked[key_to_check] = self.check_signature(
                            message.get("FLAG") + message.get("MSG"),
                            message.get("SIGN"),
                            message.get("FROM"),
                        )

                    if self.checked[key_to_check]:
                        self.check(message)

            case 2:
                counter = 0
                temp_l = message["SIGNED_VOTE_MSGS"]
                if len(temp_l) == len(self.ids) - self.faulty and not self.delivered:
                    for elem in temp_l:
                        key_to_check = (
                            elem["FLAG"],
                            elem["MSG"],
                            elem["SIGN"],
                            elem["FROM"],
                        )

                        # TODO check if it works
                        if key_to_check not in self.checked.keys():
                            print(
                                "Checking signature for message sent by",
                                elem.get("FROM"),
                            )
                            self.checked[key_to_check] = self.check_signature(
                                elem.get("FLAG") + elem.get("MSG"),
                                elem.get("SIGN"),
                                elem.get("FROM"),
                            )

                        # TODO
                        print(
                            "--- CHECKED SET FOR:",
                            elem["FLAG"],
                            elem["MSG"],
                            elem.get("FROM"),
                            self.checked[key_to_check],
                        )
                        if self.checked[key_to_check]:
                            counter += 1
                            if counter == len(self.ids) - self.faulty:
                                for i in range(len(self.ids)):
                                    self.L[i].link_send(message)
                                    self.deliver(elem["MSG"])
                                    self.__close_link()

                else:
                    logging.info(
                        "PROCESS:Already delivered not re-broadcast all the signed vote messages"
                    )
            case _:
                logging.info("PROCESS:ERROR:Received a message of type undefined")

    def __close_link(self):
        for j in range(0, len(self.ids)):
            self.L[j].ts.terminating_flag = True
            self.L[j].td.terminating_flag = True
        exit(0)

    # if you have n-f then forward this signed messages to all processes
    def check(self, message):
        temp_dict = {
            "FLAG": message["FLAG"],
            "MSG": message["MSG"],
            "SIGN": message["SIGN"],
            "FROM": message["FROM"],
        }

        self.signed_vote_messages.append(temp_dict)

        if message["MSG"] not in self.counter_signed_mess.keys():
            self.counter_signed_mess[message["MSG"]] = 0

        self.counter_signed_mess[message["MSG"]] += 1
        if self.counter_signed_mess[message["MSG"]] >= len(self.ids) - self.faulty:
            list_of_signed_msg = []
            for elem in self.signed_vote_messages:
                if elem["MSG"] == message["MSG"]:
                    list_of_signed_msg.append(elem)

            # it sends a message of type 2 so that it can access case 2 in the above function
            # TODO notice that with an high number of process list of signed messages can be huge and
            # it may create problem with socket receiving buffer
            vote_messages = {
                "SIGNED_VOTE_MSGS": list_of_signed_msg,
                "TYPE": 2,
                # "FROM": message["FROM"],
                "FROM": self.sid,
            }
            for i in range(len(self.ids)):
                self.L[i].link_send(vote_messages)

    def check_signature(self, message, signature, idn):
        # checking signature for received signed vote messages
        if str(idn) not in self.public_keys.keys():  # maybe list
            logging.info("PROCESS:Calling KDS to get public key")

            # initialize dictionary for public keys of process id=idn
            self.public_keys[str(idn)] = {}
            temp_dict = self.connection_to_KDS(idn, 0)
            self.public_keys[str(idn)]["N"] = temp_dict["KEY"]["N"]
            self.public_keys[str(idn)]["E"] = temp_dict["KEY"]["E"]

        msg = bytes(message, "utf-8")
        hash = int.from_bytes(sha512(msg).digest(), byteorder="big")
        hashFromSignature = pow(
            signature, self.public_keys[str(idn)]["E"], self.public_keys[str(idn)]["N"]
        )
        logging.info("PROCESS:Signature check exit:<%r>", hash == hashFromSignature)
        print("check executed")
        return hash == hashFromSignature

    def make_signature(self, message):
        # generating keys
        if not self.key_gen:
            logging.info("PROCESS:Calling KDS to get key pair")
            self.key_gen = True
            self.keyPair = self.connection_to_KDS(self.sid, 1)

        # sign
        msg = bytes(message, "utf-8")
        hash = int.from_bytes(sha512(msg).digest(), byteorder="big")
        signature = pow(hash, self.keyPair["D"], self.keyPair["N"])
        logging.info("PROCESS:Signature:<%s>", hex(signature))
        return signature

    def connection_to_KDS(self, idn, typ):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.connect((KDS_IP, KDS_PORT))
            logging.info("PROCESS:Connecting to KDS")
            # getting key pair from KDS
            pack = {}
            pack["FROM"] = idn
            pack["TYPE"] = typ
            send_pack = json.dumps(pack)
            sock.sendall(send_pack.encode())
            data = sock.recv(RCV_BUFFER_SIZE)
            parsed_data = json.loads(data.decode())
            # return a dict containing
            return parsed_data

    def deliver(self, message):
        # delivering the final message
        print("-----MESSAGE DELIVERED:", message, "-----")

        peak = self.eval.tracing_mem()
        logging.info(
            "-----MESSAGE DELIVERED: %s, time: %s, size: %s",
            message,
            time.time() * 1000,
            peak,
        )
        self.delivered = True
