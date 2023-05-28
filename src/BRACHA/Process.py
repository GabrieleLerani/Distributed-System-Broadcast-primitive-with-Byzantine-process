import math
import threading
import time
import logging
import psutil
import BRACHA.utils as utils
from threading import Thread
from BRACHA.AuthenticatedLink import AuthenticatedLink

from BRACHA.Evaluation import Evaluation


BREAK_TIME = 0.04


class Process:
    def __init__(self):
        self.ids = []
        self.ips = []
        self.currentMSG = []
        self.selfip = 0
        self.selfid = 0
        self.AL = []
        self.sentecho = False
        self.sentready = False
        self.delivered = False
        self.echos = {}
        self.readys = {}
        self.faulty = 0
        self.eval = Evaluation()

    def init_process(self):
        # Start tracing memory for statistics
        self.eval.tracing_start()
        # Populate ids ips from file
        self.init_process_ids()
        logging.debug("PROCESS: id list: %s,ip list %s", self.ids, self.ips)
        print("-----GATHERED ALL THE PEERS IPS AND IDS-----")
        print("-----STARTING SENDING OR RECEIVING MESSAGES-----")
        t = Thread(target=self.__thread)
        t.start()

    def init_process_ids(self):
        processes = utils.read_process_identifier()
        for pair in processes:
            self.ids.append(int(pair[0]))  # pair[0] --> ID
            self.ips.append(pair[1])  # pair[1] --> IPS

    # Without server is enough to make self.AL[i].receiver() once
    def creation_links(self):
        self.selfip = utils.get_ip_of_interface()
        self.selfid = self.ids[self.ips.index(self.selfip)]
        self.barrier = threading.Barrier(parties=2)

        for i in range(0, len(self.ids)):
            self.AL.append(
                AuthenticatedLink(
                    self.selfid,
                    self.selfip,
                    self.ids[i],
                    self.ips[i],
                    self,
                )
            )
            self.AL[i].receiver()

        for i in range(0, len(self.ids)):
            self.AL[i].key_exchange()

    def __thread(self):
        while True:
            for msg in self.currentMSG:
                counter_echos = 0
                counter_readys = 0

                for i in self.echos.values():
                    if i == msg:
                        counter_echos += 1
                for i in self.readys.values():
                    if i == msg:
                        counter_readys += 1

                if (
                    counter_echos > math.floor((len(self.ids) + self.faulty) / 2)
                ) and self.sentready is False:
                    self.sentready = True

                    # Broadcast to all a ready message
                    for i in range(len(self.ids)):
                        if msg not in self.currentMSG:
                            self.currentMSG.append(msg)

                        packet = {"MSG": msg, "FLAG": "READY"}
                        self.AL[i].send(packet)

                if counter_readys > self.faulty and self.sentready is False:
                    self.sentready = True

                    # Broadcast to all a ready message
                    for i in range(len(self.ids)):
                        if msg not in self.currentMSG:
                            self.currentMSG.append(msg)

                        packet = {"MSG": msg, "FLAG": "READY"}
                        self.AL[i].send(packet)

                if counter_readys > 2 * self.faulty and self.delivered is False:
                    self.delivered = True

                    # End execution time
                    end_time = time.time() * 1000

                    # Memory used
                    peak = self.eval.tracing_mem()

                    logging.info(
                        "----- MESSAGE DELIVERED, time: %s, size: %s",
                        end_time,
                        peak,
                    )

                    print("----- MESSAGE DELIVERED:", msg)
                    logging.info("BYTES SENT: %d", self.__get_bytes_sent() / 1024)

                    return

            # Not to destroy performance
            time.sleep(BREAK_TIME)

    # Before starting broadcast, a process reads the ip addresses and ids of
    # the other processes from its queue

    # The message is sent using authenticated link abstractions, it's a string with a flag indicating
    # the type {SEND,ECHO,READY}
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

        # Create packet as a dictionary
        packet = {"MSG": message, "FLAG": "SEND"}
        for i in range(len(self.ids)):
            if message not in self.currentMSG:
                self.currentMSG.append(message)
            self.AL[i].send(packet)
        self.barrier.wait()

    def deliver_send(self, msg, idn):
        if msg["FLAG"] == "SEND" and idn == 1 and self.sentecho is False:
            # Add the message if it's not yet received
            if msg["MSG"] not in self.currentMSG:
                self.currentMSG.append(msg["MSG"])
            self.sentecho = True
            if self.selfid == 1:
                self.barrier.wait()

            # create packet
            packet = {"MSG": msg["MSG"], "FLAG": "ECHO"}
            for i in range(len(self.ids)):
                self.AL[i].send(packet)
        elif idn != 1:
            logging.info("PROCESS: %d is not the intended sender!", idn)

    def deliver_echo(self, msg, idn):
        if msg["FLAG"] == "ECHO" and idn not in self.echos:
            if msg["MSG"] not in self.currentMSG:
                self.currentMSG.append(msg["MSG"])
            self.echos[idn] = msg["MSG"]

            logging.info("PROCESS: --------ECHOS VALUE: %s:", self.echos)

    def deliver_ready(self, msg, idn):
        if msg["FLAG"] == "READY" and idn not in self.readys:
            if msg["MSG"] not in self.currentMSG:
                self.currentMSG.append(msg["MSG"])
            self.readys[idn] = msg["MSG"]

            logging.info("PROCESS: --------READYS VALUE: %s:", self.readys)

    def __get_bytes_sent(self):
        sent = 0
        for i in range(0, len(self.AL)):
            sent += self.AL[i].bytes_sent
        return sent
