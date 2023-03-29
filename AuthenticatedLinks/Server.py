import socket
from threading import Thread
import pika
import utils
import logging

RCV_BUFFER_SIZE = 1024
JSON_DELIMITER = '\n'


class TCP_SERVER:

    def __init__(self):
        self.N = 10
        self.IDS = []
        self.IPS = []
        self.IDS_size = 0
        self.IPS_size = 0
        self.t = 0
        self.current_IP = None
        self.IP = None
        self.PORT = 5000

    def do_get(self):
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the port
        # self.IP = socket.gethostbyname('localhost')

        self.IP = '192.168.1.40'
        server_address = (self.IP, self.PORT)
        # print(sys.stderr, ' SERVER: starting up on %s port %s' % server_address)
        logging.info(' SERVER: starting up on %s port %s' % server_address)

        sock.bind(server_address)
        # Listen for incoming connections
        sock.listen(self.N)

        while True:
            # Wait for a connection from a process
            # print(sys.stderr, 'SERVER: waiting for a connection')
            logging.info('SERVER: waiting for a connection')
            connection, client_address = sock.accept()

            with connection:

                logging.debug('SERVER: connection from %s', client_address)

                # Receive the data in small chunks and retransmit it
                while True:
                    # first hello message
                    data = connection.recv(RCV_BUFFER_SIZE)
                    # print(sys.stderr, 'SERVER: received "%s"', data)
                    logging.debug('SERVER: received "%s"', data)
                    if data:
                        # print(sys.stderr, 'SERVER: sending data back to the client')
                        logging.debug('SERVER: sending data back to the client')
                        # advertising the peers of a new peer
                        # sending back to client process the address of the socket's thread
                        # updating global information
                        if client_address[0] not in self.IPS:
                            self.IDS_size += 1
                            for p_id in range(1, self.IDS_size + 1):
                                t = Thread(target=self.thread_trigger, args=(client_address, p_id))
                                t.start()
                            self.IPS.append(client_address[0])
                            self.IPS_size += 1

                            self.IDS.append(self.IDS_size)
                        self.t += 1
                        # creating thread
                        t = Thread(target=self.thread_conn, args=(self.t, client_address))
                        t.start()
                        # sending information
                        connection.sendall(bytes(str(self.t), 'utf-8'))

                    else:
                        logging.debug('SERVER: no more data from %s', client_address)
                        break

    def thread_conn(self, t, c_address):

        # Create a TCP/IP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            # Bind the socket to the port
            server_address = (self.IP, self.PORT + t)

            logging.debug(' THREAD_CONN: starting up on %s port %s', server_address[0],server_address[1])

            sock.bind(server_address)
            # Listen for incoming connections
            sock.listen(0)

            while True:
                # Wait for a connection from a process

                logging.debug('THREAD_CONN: waiting for a connection')
                connection, client_address = sock.accept()

                with connection:
                    logging.debug('THREAD_CONN: connection from %s', client_address)

                    # Receive the data in small chunks and retransmit it
                    while True:
                        # second hello message
                        data = connection.recv(RCV_BUFFER_SIZE)

                        if data:

                            logging.debug('THREAD_CONN: received %s', data)

                            logging.debug('THREAD_CONN: sending data back to the client')
                            # sending back to client process the address of the socket's thread
                            # creating dictionary for the process
                            # print("THREAD_CONN: sending dictionaries of ips list:", self.IPS)
                            logging.debug("THREAD_CONN: sending dictionaries of ips list: %s", self.IPS)

                            for i in range(self.IDS_size):
                                if self.IPS[i] != c_address:
                                    proc_dict = {
                                        'IP': self.IPS[i],
                                        'ID': self.IDS[i]
                                    }
                                    payload = utils.serialize_json(proc_dict)
                                    connection.sendall(payload)

                            end_message = utils.serialize_json('END')
                            connection.sendall(end_message)

                            logging.info("THREAD_CONN: dictionaries of ips list sent successfully")

                        else:

                            logging.debug('THREAD_CONN: no more data from %s', client_address)
                            break

    def thread_trigger(self, c_address, queue_id):
        # creating queue

        logging.debug('THREAD_QUEUE: creating queue for %s', c_address)
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=self.IP))  # Connect to CloudAMQP
        channel = connection.channel()  # start a channel
        channel.queue_declare(queue=str(queue_id))  # naming queue
        channel.basic_publish(exchange='', routing_key=str(queue_id),
                              body=bytes(str(c_address[0]) + '#' + str(self.IDS_size), 'utf-8'))
        connection.close()  # closing connection
        logging.debug('THREAD_QUEUE: closing queue for %s', c_address)
