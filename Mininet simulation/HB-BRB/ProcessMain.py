import time
import Process
import sys
import utils
import signal
import os

TIME_SLEEP = 8


if __name__ == "__main__":
    if len(sys.argv) > 2:
        print("ssage: python ProcessMain.py <broadcast message>")
        exit(-1)
    elif len(sys.argv) == 2:
        message = sys.argv[1]

        utils.set_process_logging(0, 0, 0)
        p = Process.Process()

        p.init_process()
        p.creation_links()
        time.sleep(TIME_SLEEP)
        p.broadcast(message)
        utils.end_app(os.getpid(),4)
        

    else:
        utils.set_process_logging(0, 0, 0)
        p = Process.Process()
        p.init_process()
        p.creation_links()
        utils.end_app(os.getpid(),15)
        

    exit(0)


