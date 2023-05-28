from threading import Thread
import logging
from sys import platform
from hashlib import sha512
from Process import Process
import random


KDS_IP = "10.0.0.1"
KDS_PORT = 8080

RCV_BUFFER_SIZE = 32768
BREAK_TIME = 0.1

BROADCASTER_ID = 1

PLACEHOLDER = "vote_msg"


# This process forges a type 1 message (VOTE message) and a whole type 2 message (SIGNED_VOTE_MSGS)
class ByzantineProcess(Process):
    def __init__(self):
        super().__init__()
        self.byz_mess = "byz_mess"

    def process_receive(self, message):
        # receive messages from the underlying pppl
        match message.get("TYPE"):
            case 0:
                
                if len(self.public_keys) == 0:
                    self.get_process_keys()
                

                if (
                    message.get("FROM") == BROADCASTER_ID
                    and message.get("FLAG") == "PROPOSE"
                ):
                    # forging a type 1 message
                    msg = {}
                    msg["FLAG"] = "VOTE"
                    msg["MSG"] = self.byz_mess
                    msg["SIGN"] = self.make_signature(msg.get("FLAG") + self.byz_mess)
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
                        
                        self.checked[key_to_check] = self.check_signature(
                            message.get("FLAG") + message.get("MSG"),
                            message.get("SIGN"),
                            message.get("FROM"),
                        )

                    if self.checked[key_to_check]:
                        self.check(message)

            case 2:
                # used to count verified message, if n - f then deliver
                counter = 0

                # store into a temp variable list of forwarded signed messages
                temp_l = message["SIGNED_VOTE_MSGS"]
                
                print("SIGNED VOTE MSGS",temp_l)
                if len(temp_l) == len(self.ids) - self.faulty and not self.delivered:
                    
                    # used to take trace for how many signs for a message
                    messages = {}
                    
                    for elem in temp_l:
                        # temp key to reduce redundancy
                        key_to_check = (
                            elem["FLAG"],
                            elem["MSG"],
                            elem["SIGN"],
                            elem["FROM"],
                        )

                        # check whether the message signature has already been checked
                        if key_to_check not in self.checked.keys():
                            
                            # if no then check and store it
                            self.checked[key_to_check] = self.check_signature(
                                elem["FLAG"] + elem["MSG"],
                                elem["SIGN"],
                                elem["FROM"],
                            )

                        # if signature is valid and the current message is really a VOTE increase the counter
                        if self.checked[key_to_check] and "VOTE" == elem["FLAG"]:
                            counter += 1
                            messages[elem["MSG"]] = counter
                            
                            # check whether there is a signed vote message with at least n - f signs
                            # it is used to avoid to deliver a last message which is forged by the byzantine process
                            msg_to_deliver = self.there_is_message(messages)
                            print(messages)
                            # when you have n-f valid message commit and close link
                            if counter == len(self.ids) - self.faulty:
                                for i in range(len(self.ids)):
                                    self.L[i].link_send(message)
                                    self.deliver(msg_to_deliver)
                                    self.close_link()
                                
                else:
                    logging.info(
                        "PROCESS:Already delivered not re-broadcast all the signed vote messages"
                    )
            case _:
                logging.info("PROCESS:ERROR:Received a message of type undefined")

    # if you have n-f then forward this signed messages to all processes
    def check(self, message):
        # forging a byzantine messsage
        # there are many fields that could be modified, but they just do not make any sense:
        # - FLAG: it would be immediately discarded because only VOTE messages are accepted
        # - FROM: by modifying only it, the public key used to check the signature would belong to a different process so the check would fail
        # - FROM , SIGN: by modifying both of them, the problem would be only postponed because, 
        #                although the public key would be the correct one, the check would fail anyway
        # by modifying MSG, SIGN and FROM fields the check will fail only at the end
        # furthermore, by adding a random number at the end of the byzantine message, 
        # the receiver will be forced to check all the messages contained in the data structure
        rand = str(random.randint(0, 30))
        byz_dict = {
            "FLAG": message["FLAG"],
            "MSG": self.byz_mess + rand,
            "SIGN": self.make_signature(message.get("FLAG") + self.byz_mess + rand),
            "FROM": self.sid,
        }

        self.signed_vote_messages.append(byz_dict)

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
                "FROM": self.sid,
            }
            for i in range(len(self.ids)):
                self.L[i].link_send(vote_messages)
                