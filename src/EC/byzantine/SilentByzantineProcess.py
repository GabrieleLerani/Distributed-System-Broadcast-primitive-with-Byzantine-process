import logging
from EC.Process import Process


RCV_BUFFER_SIZE = 16384
BREAK_TIME = 0.1

BROADCAST_ID = 1


# This byzantine process does not answer to any messages it receives
class ByzantineProcess(Process):
    def __init__(self):
        super().__init__()

    def receiving_msg(self, message):
        logging.info("%s is the MSG received",message)
        

    def receiving_echo(self, echo):
        
        logging.info("%s is the ECHO received",echo)
        

    def receiving_acc(self, acc):
        
        logging.info("%s is the ACC received",acc)
        

    def receiving_req(self, req):
        logging.info("%s is the REQ received",req)
        


