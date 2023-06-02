import logging
import time
import hashlib
import EC.utils as utils
from EC.Process import Process


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

            # get codeword from message m
            self.codeword = utils.encode(self.first_byz_mess, self.k, len(self.ids))
            self.second_codeword = utils.encode(self.second_byz_mess, self.k, len(self.ids))

            # send message to all other along with the corresponding coded element
            for i in range(len(self.ids)):

                message_to_send = {}
                if i < self.faulty:

                    message_to_send = {
                        "FLAG": "MSG",
                        "FROM": str(self.selfid),
                        "SOURCE": str(self.selfid),
                        "HASH": self.__hash(self.first_byz_mess),
                        "C": list(self.codeword[i]),
                        "SEQUENCENUMBER": str(self.h),
                    }
                else:
                    message_to_send = {
                        "FLAG": "MSG",
                        "FROM": str(self.selfid),
                        "SOURCE": str(self.selfid),
                        "HASH": self.__hash(self.second_byz_mess),
                        "C": list(self.second_codeword[i]),
                        "SEQUENCENUMBER": str(self.h),
                    }

                
                self.AL[i].send(message_to_send)
                print(f"Forged messages sent to {i + 1}") 
            
    @staticmethod
    def __hash(message):
        return hashlib.sha256(bytes(message, "utf-8")).hexdigest()