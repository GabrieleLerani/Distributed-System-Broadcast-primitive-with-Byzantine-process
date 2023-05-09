from socketserver import BaseRequestHandler, TCPServer
import logging
import socket
import json
import threading

RCV_BUFFER_SIZE = 8192
LINK_R = {}
G_IP = {}
G_PORT = {}


class handler(BaseRequestHandler):
    def handle(self):
        global LINK_R  # to specify that we want to modify the global variable
        while True:
            data = self.request.recv(RCV_BUFFER_SIZE)
            if not data:
                break
            parsed_data = json.loads(data.decode())

            # TODO to fix this logging
            # logging.info("LINK_H: received this data %s from <%s,%d>", parsed_data, G_IP.get(parsed_data.get('FROM')),
            #             G_PORT.get(parsed_data.get('FROM')))
            LINK_R.get(str(parsed_data.get("FROM"))).link_receive(parsed_data)


class tcp_rx:
    def __init__(self, link, IP, PORT, IDN):
        global LINK_R  # to specify that we want to modify the global variable
        LINK_R[str(IDN)] = link  # ref to upper link module
        self.IP = IP
        self.PORT = PORT
        self.terminating_flag = False

    def run(self):
        with TCPServer((self.IP, self.PORT), handler) as server:
            # Start processing requests
            thread = threading.Thread(target=self.run_handle, args=(server,))
            thread.start()

            # ... do things ...

            # Shutdown server
            while True:
                if self.terminating_flag:
                    logging.info("LINK_H: Closing receiving interface")
                    server.shutdown()
                    exit(0)

    def run_handle(self, server):
        server.serve_forever()


class tcp_snd:
    def __init__(self, IP, PORT, IDN):
        self.sending_flag = False
        self.sending_msg = {}
        global G_IP
        G_IP[str(IDN)] = IP
        global G_PORT
        G_PORT[str(IDN)] = PORT
        self.IP = IP
        self.PORT = PORT
        self.terminating_flag = False

    def run(self):
        while True:
            while not self.sending_flag:
                if self.terminating_flag:
                    logging.info("LINK_H: Closing sending interface")
                    exit(0)
            logging.info(
                "LINK_H:Sending message to process<%s>,<%d>", self.IP, self.PORT
            )

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.connect((self.IP, self.PORT))
                # marshal message
                parsed_data = json.dumps(self.sending_msg)
                sock.sendall(parsed_data.encode())
                self.sending_flag = False
                logging.info("LINK_H:Message sent successfully")
            except:
                break  # TODO solve break