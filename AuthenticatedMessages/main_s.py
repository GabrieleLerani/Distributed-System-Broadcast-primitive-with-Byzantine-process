import Server
import logging
import asyncore
import KDS

if __name__ == "__main__":
    # dummy main for starting servers
    logging.basicConfig(filename="debug.log", filemode="w", level=logging.INFO)
    # initializing servers
    logging.info("MAIN_S:Starting ID Server ")
    s = Server.TCP_SERVER()
    logging.info("MAIN_S:Starting KDS Server ")
    server = KDS.KDSServer('localhost', 8080)
    # starting servers
    asyncore.loop()
    logging.info("MAIN_S:KDS Server running ")
    s.do_get()
    logging.info("MAIN_S:ID Server running ")
