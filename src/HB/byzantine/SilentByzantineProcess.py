import logging
from HB.Process import Process


RCV_BUFFER_SIZE = 16384
BREAK_TIME = 0.1

BROADCAST_ID = 1


# This byzantine process echoes the packets it receives but does not answer to any of them
class ByzantineProcess(Process):
    def __init__(self):
        super().__init__()

    def receiving_msg(self, message, id):
        logging.info("%s is the MSG received from %d",message,id)
        

    def receiving_echo(self, echo, id):
        if self.first(echo, "ECHO", id):
            logging.info("%s is the ECHO received from %d",echo,id)
            

    def receiving_acc(self, acc, id):
        if self.first(acc, "ACC", id):
            logging.info("%s is the ACC received from %d",acc,id)
            

    def receiving_req(self, req, id):
        if self.first(req, "REQ", id):
            logging.info("%s is the REQ received from %d",req,id)
            

    def first(self, message, flag, sender):
        if flag == "ECHO":
            if [
                "ECHO",
                message["Source"],
                message["SequenceNumber"],
                sender,
            ] not in self.echos_rec:
                self.echos_rec.append(
                    ["ECHO", message["Source"], message["SequenceNumber"], sender]
                )
                return True
            return False
        elif flag == "ACC":
            if [
                "ACC",
                message["Source"],
                message["SequenceNumber"],
                sender,
            ] not in self.accs_rec:
                self.accs_rec.append(
                    ["ACC", message["Source"], message["SequenceNumber"], sender]
                )
                return True
            return False
        elif flag == "REQ":
            if [
                "REQ",
                message["Source"],
                message["SequenceNumber"],
                sender,
            ] not in self.reqs_rec:
                self.reqs_rec.append(
                    ["REQ", message["Source"], message["SequenceNumber"], sender]
                )
                return True
            return False
