import hashlib
import logging
import time
import HB.utils as utils
from HB.Process import Process


RCV_BUFFER_SIZE = 16384
BREAK_TIME = 0.1

BROADCAST_ID = 1


# This byzantine process behaves exactly like other processes but instead of sending correct message, it forges a new one and sends it
class ByzantineProcess(Process):
    def __init__(self):
        super().__init__()
        self.byz_mess = utils.generate_payload(256)

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

            if [
                "ECHO",
                message["Source"],
                message["SequenceNumber"],
            ] not in self.echos_sent:
                self.echos_sent.append(
                    ["ECHO", message["Source"], message["SequenceNumber"]]
                )
                hashed_message = self.__hash(self.byz_mess)
                
                packet = {
                    "Flag": "ECHO",
                    "Source": self.selfid,  # TODO Non sono sicuro che self.selfid sia riconsciuto da una classe figlia
                    "Message": hashed_message,
                    "SequenceNumber": message["SequenceNumber"],
                }

                for i in range(len(self.AL)):
                    self.AL[i].send(packet)

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
                logging.info("MSG SET %s", self.MsgSets)

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

                        hashed_message = self.__hash(self.byz_mess)

                        packet = {
                            "Flag": "ECHO",
                            "Source": source,
                            "Message": hashed_message,
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

                        hashed_message = self.__hash(self.byz_mess)

                        packet = {
                            "Flag": "ACC",
                            "Source": source,
                            "Message": hashed_message,
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

                        hashed_message = self.__hash(self.byz_mess)

                        packet = {
                            "Flag": "ACC",
                            "Source": source,
                            "Message": hashed_message,
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
                                f"-----MESSAGE DELIVERED: {msg} -----",
                            )

                            peak = self.eval.tracing_mem()
                            logging.info(
                                "-----MESSAGE DELIVERED, time: %s, size: %s",
                                time.time() * 1000,
                                peak,
                            )

                        logging.info("BYTES SENT: %d", self.get_bytes_sent() / 1024)