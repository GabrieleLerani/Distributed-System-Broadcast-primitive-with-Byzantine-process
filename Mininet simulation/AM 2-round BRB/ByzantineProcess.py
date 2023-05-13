from threading import Thread
import logging
from sys import platform
from hashlib import sha512
from Process import Process


KDS_IP = "10.0.0.1"
KDS_PORT = 8080

RCV_BUFFER_SIZE = 32768
BREAK_TIME = 0.1

BROADCASTER_ID = 1

PLACEHOLDER = "vote_msg"


# This process forges a type 1 message (VOTE message) and only the last part of a type 2 message (SIGNED_VOTE_MSGS)
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
                        # set for that specific key the check signature result so that it's not
                        # required to check twice the same message
                        self.checked[key_to_check] = self.check_signature(
                            message.get("FLAG") + message.get("MSG"),
                            message.get("SIGN"),
                            message.get("FROM"),
                        )

                    
                    if self.checked[key_to_check]:
                        # if signature is valid then check whether you have n - f signed VOTE messages
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
            
            # forging a byz mess and inserting at the end of the list of n - f messages
            byz_dict = {
                "FLAG": message["FLAG"],
                "MSG": self.byz_mess,
                "SIGN": self.make_signature(message.get("FLAG") + self.byz_mess),
                "FROM": message["FROM"],
            }
            list_of_signed_msg[len(list_of_signed_msg) - 1] = byz_dict

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
            