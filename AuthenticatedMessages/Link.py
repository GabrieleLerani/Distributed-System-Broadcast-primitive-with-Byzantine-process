import socket
import hashlib
import hmac
import json
import logging
from threading import Thread
import threading
import Link_handler


class Link:
    def __init__(self, sid, sip, idn, ip,process):
        self.sid = sid  # id of this process
        self.id = idn  # id of other process
        self.sip = sip # ip of this process
        self.ip = ip # ip of the other process
        self.process=process # process instance to callback for arrived messages
        self.thread=None # ref to TCP/IP socket interface thread

    def build_Link_r(self):
        # modelling the rx side of the link
        # It uses ternary operator
        logging.info("LINK:Creating link for receiving from <%s,%d>",self.ip,self.id)
        port = (
            int("50" + str(self.id) + str(self.sid))
            if self.sid < 10 and self.id < 10
            else int("5" + str(self.id) + str(self.sid))
        )
        l=Link_handler.tcp_rx(self,sip,port,self.id)
        thread = Thread(target = l.run, args = ())
        thread.start()

    def build_Link_s(self):
        # modelling the rx side of the link
        # It uses ternary operator
        logging.info("LINK:Creating link for sending to <%s,%d>",self.ip,self.id)
        port = (
            int("50" + str(self.self_id) + str(self.id))
            if self.self_id < 10 and self.id < 10
            else int("5" + str(self.self_id) + str(self.id))
        )
        l=link.handler.tcp_snd(self.ip,port,self.id)
        self.thread = Thread(target = l.run, args = ())
        self.thread.start()

    def link_receive(self,msg):# to call the upper module
        logging.info("LINK:Forwarding message to process module from Link module")
        self.process.process_receive(msg)
        
    def link_send(self,msg):
        self.thread.sending_msg=msg
        self.thread.sending_flag=True
        logging.info("LINK:Sending message to Link_handler module from Link module")

        
        