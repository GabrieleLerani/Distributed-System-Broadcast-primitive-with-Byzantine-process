from threading import Thread
import logging
import Process
import sys
import time
import utils
import Evaluation


TIME_BEFORE_BROADCAST = 2


if __name__ == "__main__":
    if len(sys.argv) > 3:
        print("Usage: python PythonMain.py <broadcast message> <sim number>")
        exit(-1)

    # Since all the processes share the same code it's required to differentiate
    # sender from receiver
    # Simulation number is used to initialize correctly simulation folders
    elif len(sys.argv) == 3:
        message = sys.argv[1]
        sim_num = sys.argv[2]

        utils.set_process_logging(sim_num)
        logging.info("MAIN:STARTING PROTOCOL--> BYZANTINE RELIABLE BROADCAST")
        p = Process.Process()

        p.connection_to_server()
        p.creation_links()

        # Timer is used to allow other processes to start and initialize connections between them
        time.sleep(TIME_BEFORE_BROADCAST)

        # Start broadcast
        p.broadcast(message)

    else:
        sim_num = sys.argv[1]

        utils.set_process_logging(sim_num)
        logging.info("MAIN:STARTING PROTOCOL--> BYZANTINE RELIABLE BROADCAST")

        p = Process.Process()

        # eval = Evaluation.Evaluation()

        # eval.tracing_start()
        p.connection_to_server()
        p.creation_links()

    exit(0)
