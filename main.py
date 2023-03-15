import sys
from threading import Thread
import logging
import Server
import Process


def thread1():
    server = Server.TCP_SERVER()
    server.do_get()


if __name__ == "__main__":
    
    logging.basicConfig(filename='debug.log', filemode='w',encoding='utf-8', level=logging.DEBUG)
    t = Thread(target=thread1,)
    t.start()
    logging.info('MAIN:STARTING PROTOCOL--> BYZANTINE RELIABLE BROADCAST')
    process=Process.process()
    process.start()
    logging.info('MAIN:ENDING PROTOCOL--> BYZANTINE RELIABLE BROADCAST')
    logging.info('MAIN:SUCCESSFUL EXIT')
    exit(0)

