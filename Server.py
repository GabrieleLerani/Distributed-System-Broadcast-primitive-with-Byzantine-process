import socket
import sys
from threading import Thread


class TCP_SERVER:

    def __init__(self):
        self.N = 10
        self.IDS = []
        self.IPS = []
        self.IDS_size = 0
        self.IPS_size = 0
        self.t = 0

    def do_get(self):
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the port
        server_address = ('localhost', 5000)
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
                    print(sys.stderr, 'received "%s"' % data)
                    if data:
                        print(sys.stderr, 'sending data back to the client')

                        # sending back to client process the address of the socket's thread
                        # updating global information
                        self.IPS.append(client_address)
                        self.IPS_size += 1
                        self.IDS_size += 1
                        self.IDS.append(self.IDS_size)
                        self.t += 1
                        # creating thread
                        t = Thread(target=self.thread_conn, args=(self.t,))
                        t.start()
                        # sending information
                        connection.sendall(bytes(str(self.t)))

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
        server_address = ('localhost', 5000 + t)
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
                        connection.sendall(bytes([self.IDS_size, self.IDS, self.IPS_size, self.IPS]))
                    else:
                        print(sys.stderr, 'no more data from', client_address)
                        break

            finally:
                # Clean up the connection
                connection.close()
