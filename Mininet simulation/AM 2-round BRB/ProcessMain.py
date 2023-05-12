import Byzantine.ByzantineProcess as ByzantineProcess
import Byzantine.ByzantineProcess1 as ByzantineProcess1
import Byzantine.SilentByzantineProcess as SilentByzantineProcess
import time
import Process
import sys
import utils
import os

TIME_SLEEP = 10


if __name__ == "__main__":
    if len(sys.argv) > 3:
        print(
            "usage: python ProcessMain.py <broadcast message> [Normal,Byzantine,SilentByzantine]"
        )
        exit(-1)

    elif len(sys.argv) == 3:
        message = sys.argv[1]
        type = sys.argv[2]
        utils.set_process_logging(0, 0, 0)
        p = Process.Process()
        p.init_process()
        p.creation_links()
        time.sleep(TIME_SLEEP)
        p.broadcast(message)
        utils.end_app(os.getpid(), 60)

    else:
        utils.set_process_logging(0, 0, 0)
        type = sys.argv[1]

        if type == "Normal":
            p = Process.Process()
            p.init_process()
            p.creation_links()
            utils.end_app(os.getpid(), 60)

        elif type == "Byzantine":
            p = ByzantineProcess.ByzantineProcess()
            p.init_process()
            p.creation_links()
            utils.end_app(os.getpid(), 60)
        
        elif type == "Byzantine1":
            p = ByzantineProcess1.ByzantineProcess()
            p.init_process()
            p.creation_links()
            utils.end_app(os.getpid(), 60)
        

        elif type == "SilentByzantine":
            p = SilentByzantineProcess.SilentProcess()
            p.init_process()
            p.creation_links()
            utils.end_app(os.getpid(), 60)

    exit(0)
