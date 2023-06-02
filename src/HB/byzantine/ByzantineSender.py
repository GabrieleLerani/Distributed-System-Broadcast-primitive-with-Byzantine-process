import logging
import time
import hashlib
import HB.utils as utils
from HB.Process import Process


RCV_BUFFER_SIZE = 16384
BREAK_TIME = 0.1



BROADCASTER_ID = 1
DROP_MSG_ID = 100  # specify the id of the process which drops message with flag MSG
DROP_ECHO_ID = 100  # specify the id of the process which drops message with flag ECHO



# This byzantine sends to n - 1 / 3 a message and to other n - f a different message
class ByzantineProcess(Process):
    def __init__(self):
        super().__init__()
        self.first_byz_mess = utils.generate_payload(256)
        self.second_byz_mess = utils.generate_payload(256)
        self.second_codeword = []


    def broadcast(self, *args):
        response = ""
        size = 0

        if len(args) > 0:
            self.first_byz_mess = utils.generate_payload(size)
            self.second_byz_mess = utils.generate_payload(size)
        else:
            response = str(input("Start sending random message? [Y/n] "))
        
        if response == "Y":
            

            logging.info(
                "----- EVALUATION CHECKPOINT: broadcast start, time: %s -----",
                time.time() * 1000,
            )

            first_packet = {
                "Flag": "MSG",
                "Source": self.selfid,
                "Message": self.first_byz_mess,
                "SequenceNumber": self.h,
            }

            second_packet = {
                "Flag": "MSG",
                "Source": self.selfid,
                "Message": self.second_byz_mess,
                "SequenceNumber": self.h,
            }

            for i in range(len(self.AL)):
                if i < self.faulty:
                    self.AL[i].send(first_packet)
                else:
                    self.AL[i].send(second_packet)
                print(f"Forged messages sent to {i + 1}") 
            self.barrier.wait()
            


    @staticmethod
    def __hash(message):
        return hashlib.sha256(bytes(message, "utf-8")).hexdigest()