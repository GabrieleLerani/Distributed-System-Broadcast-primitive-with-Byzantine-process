
LINK_R=None
from socketserver import BaseRequestHandler, TCPServer

class handler(BaseRequestHandler):
    def handle(self):
        global LINK_R
        while True:
            data = self.request.recv(1024)
            if not data:
                break
            print("the link is :",LINK_R)

class tcp_rx:
    def __init__(self,link,IP,PORT):
        global LINK_R # ref to upper link module
        LINK_R=link
        self.IP=IP
        self.PORT=PORT
    def run(self):
        with TCPServer((self.IP, self.PORT), handler) as server:
            server.serve_forever()
   
           
