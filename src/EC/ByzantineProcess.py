import hashlib
import logging
import EC.utils as utils
from EC.Process import Process


RCV_BUFFER_SIZE = 16384
BREAK_TIME = 0.1



BROADCASTER_ID = 1
DROP_MSG_ID = 100  # specify the id of the process which drops message with flag MSG
DROP_ECHO_ID = 100  # specify the id of the process which drops message with flag ECHO



# This byzantine process behaves exactly like other processes but instead of sending correct message, it forges a new one and sends it
class ByzantineProcess(Process):
    def __init__(self):
        super().__init__()
        self.byz_mess = utils.generate_payload(256)
        self.byz_codeword = []

    # message must be a string
    @staticmethod
    def __hash(message):
        return hashlib.sha256(bytes(message, "utf-8")).hexdigest()

    def receiving_msg(self, msg):
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

                    # get codeword from message m
                    self.byz_codeword = utils.encode(self.byz_mess, self.k, len(self.ids))

                    # send message to all other along with the corresponding coded element
                    for i in range(len(self.ids)):
                        message_to_send = {
                            "FLAG": "ECHO",
                            "FROM": str(self.selfid),
                            "SOURCE": str(self.selfid),
                            "HASH": self.__hash(self.byz_mess),
                            "C": list(self.byz_codeword[i]),
                            "SEQUENCENUMBER": str(self.h),
                        }

                        self.AL[i].send(message_to_send)


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
                temp_codeword = utils.encode(self.byz_mess, self.k, len(self.ids))

                # send coded element within an ECHO message to all processes
                for i in range(len(self.ids)):
                    coded_element = list(temp_codeword[i])
                    packet = {
                        "FLAG": "ECHO",
                        "FROM": str(self.selfid),
                        "SOURCE": str(s),
                        "HASH": self.__hash(self.byz_mess),
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


                packet = {
                        "FLAG": "ACC",
                        "FROM": str(self.selfid),
                        "SOURCE": str(s),
                        "HASH": self.__hash(self.byz_mess),
                        "SEQUENCENUMBER": str(sn),
                    }

                for i in range(len(self.ids)):
                    self.AL[i].send(packet)
                

            elif (
                "ACC" + str(s) + str(hash_msg) + str(sn) in self.COUNTER.keys()
                and self.COUNTER["ACC" + str(s) + str(hash_msg) + str(sn)]
                >= self.faulty + 1
                and ["ACC", str(s), str(sn)] not in self.SentACC
            ):
                self.SentACC.append(["ACC", s, sn])

                packet = {
                        "FLAG": "ACC",
                        "FROM": str(self.selfid),
                        "SOURCE": str(s),
                        "HASH": self.__hash(self.byz_mess),
                        "SEQUENCENUMBER": str(sn),
                    }

                for i in range(len(self.ids)):
                    self.AL[i].send(packet)
                

            elif (
                "ACC" + str(s) + str(hash_msg) + str(sn) in self.COUNTER.keys()
                and self.COUNTER["ACC" + str(s) + str(hash_msg) + str(sn)]
                >= len(self.ids) - self.faulty
            ):
                msg = {"SOURCE": s, "MESSAGE": message, "SEQUENCENUMBER": sn}

                if not self.delivered:
                    self.delivered = True
                    self.deliver(msg["MESSAGE"])

                logging.info("BYTES SENT: %d", self.get_bytes_sent() / 1024)