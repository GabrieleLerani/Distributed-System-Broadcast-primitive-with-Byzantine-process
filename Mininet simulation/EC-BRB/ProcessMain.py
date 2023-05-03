import time
import Process
import sys
import utils

TIME_SLEEP = 8


if __name__ == "__main__":
    # TODO change input param to set logging as in Bracha algorithms
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
        p.broadcast("Hello!")
    else:
        utils.set_process_logging(0, 0, 0)
        p = Process.Process()
        p.init_process()
        p.creation_links()

    exit(0)
