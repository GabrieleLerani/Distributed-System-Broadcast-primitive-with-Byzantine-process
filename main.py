from threading import Thread
import logging
import Server


# import Process


def thread1():
    server = Server.TCP_SERVER()
    server.do_get()


if __name__ == "__main__":
    logging.basicConfig(filename='debug.log', filemode='w', level=logging.DEBUG)
    t = Thread(target=thread1, )
    t.start()
    logging.info('MAIN:STARTING PROTOCOL--> BYZANTINE RELIABLE BROADCAST')
    # p = Process.Process()
    # p.connectionToServer()
    # p.creationLinks()
    # time.sleep(5)
    # p.broadcast('Ciao')
    logging.info('MAIN:ENDING PROTOCOL--> BYZANTINE RELIABLE BROADCAST')
    logging.info('MAIN:SUCCESSFUL EXIT')
    exit(0)
