import socket
import sys
from threading import Thread
import pika
import json

IP = '192.168.27.119'
PORT = 5000


class TCP_SERVER:

    def __init__(self):
        self.N = 10
        self.IDS = []
        self.IPS = []
        self.IDS_size = 0
        self.IPS_size = 0
        self.t = 0
        self.current_IP = None

    def do_get(self):
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the port
        server_address = (IP, PORT)
        print(sys.stderr, 'starting up on %s port %s' % server_address)
        sock.bind(server_address)
        # Listen for incoming connections
        sock.listen(self.N)

        while True:
            # Wait for a connection from a process
            print(sys.stderr, 'waiting for a connection')
            connection, client_address = sock.accept()

            try:
                print(sys.stderr, 'connection from', client_address)

                # Receive the data in small chunks and retransmit it
                while True:
                    # first hello message
                    data = connection.recv(1024)
                    print(sys.stderr, 'received "%s"', data)
                    if data:
                        print(sys.stderr, 'sending data back to the client')
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
                        print(sys.stderr, 'no more data from', client_address)
                        break

            finally:
                # Clean up the connection
                connection.close()

    def thread_conn(self, t, c_address):

        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the port
        server_address = (IP, PORT + t)
        print(sys.stderr, 'starting up on %s port %s' % server_address)
        sock.bind(server_address)
        # Listen for incoming connections
        sock.listen(0)

        while True:
            # Wait for a connection from a process
            print(sys.stderr, 'waiting for a connection')
            connection, client_address = sock.accept()

            try:
                print(sys.stderr, 'connection from', client_address)

                # Receive the data in small chunks and retransmit it
                while True:
                    # second hello message
                    data = connection.recv(1024)
                    print(sys.stderr, 'received "%s"' % data)
                    if data:
                        print(sys.stderr, 'sending data back to the client')
                        # sending back to client process the address of the socket's thread
                        # creating dictionary for the process
                        for i in range(0, self.IDS_size):
                            if self.IPS[i] != c_address:
                                proc_dict = {
                                    'IP': self.IPS[i],
                                    'ID': self.IDS[i]
                                }
                                json_obj = json.dumps(proc_dict)
                                connection.sendall(bytes(json_obj, encoding='utf-8'))
                            connection.sendall(bytes("END", encoding='utf-8'))

                    else:
                        print(sys.stderr, 'no more data from', client_address)
                        break

            finally:
                # Clean up the connection
                connection.close()

    def thread_trigger(self, c_address, queue_id):
        # creating queue
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=IP))  # Connect to CloudAMQP
        channel = connection.channel()  # start a channel
        channel.queue_declare(queue=str(queue_id))  # naming queue
        channel.basic_publish(exchange='', routing_key=str(queue_id),
                              body=bytes(str(c_address[0]) + '#' + str(self.IDS_size), 'utf-8'))
        connection.close()  # closing connection
