#import asyncore
import asyncore
import logging
import socket
import json
from Crypto.PublicKey import RSA
import pickle
N = 10
KEYS = {}
RCV_BUFFER_SIZE = 8192


class KDSHandler(asyncore.dispatcher_with_send):

    def handle_read(self):
        global KEYS
        data = self.recv(RCV_BUFFER_SIZE)  # maybe size 8192

        if data:
            parsed_data = json.loads(data.decode())
            # client wants KDS to generate key pair
            if parsed_data.get('TYPE')==1:
                logging.info("KDS: request to generate public/private key pair")
                keys = RSA.generate(bits=1024)
                logging.info("Generating key for process")
                logging.info(f"Public key:  (n={hex(keys.n)}, e={hex(keys.e)})")
                logging.info(f"Private key: (n={hex(keys.n)}, d={hex(keys.d)})")
                pack = {}
                pack['E'] = keys.e
                pack['N'] = keys.n
                pack['D'] = keys.d
                send_pack = json.dumps(pack)
                self.send(send_pack.encode())

                KEYS[str(parsed_data['FROM'])] = {}
                KEYS[str(parsed_data['FROM'])]['N'] = keys.n
                KEYS[str(parsed_data['FROM'])]['E'] = keys.e
                logging.info("KDS:Public key of %s registered", parsed_data.get('FROM'))
            elif parsed_data.get('TYPE')==0:  # client wants KDS to get a public key
                logging.info("KDS: requested a public key")
                pack = {}
                pack['KEY'] = {}
                pack['KEY']['N'] = KEYS[str(parsed_data.get('FROM'))].get('N')
                pack['KEY']['E'] = KEYS[str(parsed_data.get('FROM'))].get('E')
                send_pack = json.dumps(pack)
                self.send(send_pack.encode())
                
                logging.info("KDS:Public key of %s sent", parsed_data.get('FROM'))

        else:
            logging.info("KDS:No more data from client")


class KDSServer(asyncore.dispatcher):

    def __init__(self, host, port):
        logging.info("KDS: Initializing KDS")
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(N)

    def handle_accepted(self, sock, addr):
        logging.info('SERVER: connection from %s', addr)
        handler = KDSHandler(sock)
        if not handler:
            logging.info("KDS: error in the initialization of the client handler")
            exit(-1)
