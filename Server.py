import socket
import sys


class TCP_SERVER:

    def __init__(self):
        self.IDS = []
        self.IPS = []
        self.IDS_size = 0
        self.IPS_size = 0

    def do_GET(self):
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the port
        server_address = ('localhost', 5000)
        print(sys.stderr, 'starting up on %s port %s' % server_address)
        sock.bind(server_address)
        # Listen for incoming connections
        sock.listen(1)

        while True:
            # Wait for a connection from a process
            print(sys.stderr, 'waiting for a connection')
            connection, client_address = sock.accept()

            try:
                print(sys.stderr, 'connection from', client_address)

                # Receive the data in small chunks and retransmit it
                while True:
                    self.IPS.append(client_address)
                    self.IPS_size += 1
                    data = connection.recv(16)
                    print(sys.stderr, 'received "%s"' % data)
                    if data:
                        print(sys.stderr, 'sending data back to the client')
                        self.IDS_size += 1
                        info = str(self.IDS_size) + str(self.IDS) + str(self.IPS_size) + str(self.IPS)
                        connection.sendall(bytes(info))
                    else:
                        print(sys.stderr, 'no more data from', client_address)
                        break

            finally:
                # Clean up the connection
                connection.close()
