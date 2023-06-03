import math
import logging
import time
import BRACHA.utils as utils
from BRACHA.Process import Process


RCV_BUFFER_SIZE = 16384
BREAK_TIME = 0.1

BROADCAST_ID = 1


# This byzantine process behaves exactly like other processes but instead of sending correct message, it forges a new one and sends it
class ByzantineProcess(Process):
    def __init__(self):
        super().__init__()
        self.byz_mess = utils.generate_payload(256)

    def deliver_send(self, msg, idn):
        if msg["FLAG"] == "SEND" and idn == 1 and self.sentecho is False:
            # Add the message if it's not yet received
            if msg["MSG"] not in self.currentMSG:
                self.currentMSG.append(msg["MSG"])
            self.sentecho = True
            if self.selfid == 1:
                self.barrier.wait()

            # create packet
            packet = {"MSG": self.byz_mess, "FLAG": "ECHO"}
            for i in range(len(self.ids)):
                self.AL[i].send(packet)
        elif idn != 1:
            logging.info("PROCESS: %d is not the intended sender!", idn)

    def thread(self):
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

                        packet = {"MSG": self.byz_mess, "FLAG": "READY"}
                        self.AL[i].send(packet)

                if counter_readys > self.faulty and self.sentready is False:
                    self.sentready = True

                    # Broadcast to all a ready message
                    for i in range(len(self.ids)):
                        if msg not in self.currentMSG:
                            self.currentMSG.append(msg)

                        packet = {"MSG": self.byz_mess, "FLAG": "READY"}
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
                    logging.info("BYTES SENT: %d", self.get_bytes_sent() / 1024)

                    return

            # Not to destroy performance
            time.sleep(BREAK_TIME)
