import socket


class process:
    def __init__(self):
        self.c = 0

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((socket.gethostbyname('2.tcp.eu.ngrok.io'), 17618))
            print('ciao')
            mess = bytes("Hello", "utf-8")
            s.sendall(mess)
            data = s.recv(1024)
        port = 5000 + int(data)
        print(int(data) + port)
