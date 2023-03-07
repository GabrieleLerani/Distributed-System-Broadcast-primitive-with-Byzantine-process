import socket
import sys
from threading import Thread
import pika


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
        server_address = ('192.168.1.14', 5000)
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
                            for id in range(1,self.IDS_size+1):
                                t = Thread(target=self.thread_trigger, args=(client_address,id))
                                t.start()
                            self.IPS.append(client_address[0])
                            self.IPS_size += 1

                            self.IDS.append(self.IDS_size)
                        self.t += 1
                        # creating thread
                        t = Thread(target=self.thread_conn, args=(self.t,))
                        t.start()
                        # sending information
                        connection.sendall(bytes(str(self.t), 'utf-8'))

                    else:
                        print(sys.stderr, 'no more data from', client_address)
                        break

            finally:
                # Clean up the connection
                connection.close()

    def thread_conn(self, t):

        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the port
        server_address = ('192.168.1.14', 5000 + t)
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
                        connection.sendall(bytes("IDS", 'utf-8'))
                        for i in range(0, self.IDS_size):
                            connection.sendall(bytes(str(self.IDS[i]), 'utf-8'))
                            if connection.recv(1024) != bytes(str(self.IDS[i]), 'utf-8'):
                                break
                        connection.sendall(bytes("IPS", 'utf-8'))
                        for i in range(0, self.IPS_size):
                            connection.sendall(bytes(str(self.IPS[i]), 'utf-8'))
                            if connection.recv(1024) != bytes(str(self.IPS[i]), 'utf-8'):
                                break
                        connection.sendall(bytes("END", 'utf-8'))
                    else:
                        print(sys.stderr, 'no more data from', client_address)
                        break

            finally:
                # Clean up the connection
                connection.close()

    def thread_trigger(self, c_address,id):
        # creating queue
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='192.168.1.14'))  # Connect to CloudAMQP
        channel = connection.channel()  # start a channel
        channel.queue_declare(queue=id)  # naming queue
        channel.basic_publish(exchange='', routing_key=id, body=bytes(c_address[0], 'utf-8'))
        channel.basic_publish(exchange='', routing_key=id, body=bytes(str(self.IDS_size), 'utf-8'))
        connection.close()  # closing connection
