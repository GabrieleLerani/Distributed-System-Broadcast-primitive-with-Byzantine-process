import sys
from threading import Thread

import Server
import process


def thread1():
    server = Server.TCP_SERVER()
    server.do_get()


if __name__ == "__main__":
    t = Thread(target=thread1,)
    t.start()
    print(sys.stderr,'f')
    process=process.process()
    process.start()

