from threading import Thread
import logging
import Process
import sys

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <broadcast message>")
        exit(-1)
    else:
        message = sys.argv[1]
        logging.basicConfig(filename="debug.log", filemode="w", level=logging.DEBUG)
        logging.info("MAIN:STARTING PROTOCOL--> BYZANTINE RELIABLE BROADCAST")
        p = Process.Process()
        p.connection_to_server()
        p.creation_links()
        # time.sleep(5)
        p.broadcast(message)
        logging.info("MAIN:ENDING PROTOCOL--> BYZANTINE RELIABLE BROADCAST")
        logging.info("MAIN:SUCCESSFUL EXIT")
        exit(0)
