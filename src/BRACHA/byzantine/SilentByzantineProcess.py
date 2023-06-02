import logging
from BRACHA.Process import Process


RCV_BUFFER_SIZE = 16384
BREAK_TIME = 0.1

BROADCAST_ID = 1


# This byzantine process does not answer to any messages it receives
class ByzantineProcess(Process):
    def __init__(self):
        super().__init__()

    def deliver_send(self, msg, idn):
        logging.info("Message received %s by %d",msg,idn)
        

    def deliver_echo(self, msg, idn):
        logging.info("Echo received %s by %d",msg,idn)

    def deliver_ready(self, msg, idn):
        logging.info("Ready received %s by %d",msg,idn)
        


