from threading import Thread
import logging
import Process
import Process_2
import Process_3
import sys
import time

if __name__ == "__main__":

    if ((len(sys.argv)==4) and (sys.argv[3]=='R' or sys.argv[3]=='B')) or ((len(sys.argv)==3) and (sys.argv[2]=='R' )):
        # setting up the logger file and running the selected protocol
        logging.basicConfig(filename="debug.log", filemode="w", level=logging.INFO)
        if sys.argv[2]=='R':
            check_variable=sys.argv[1]
        else:
            check_variable=sys.argv[2]

        match check_variable:

            case "1":
                logging.info("MAIN:STARTING PROTOCOL--> BYZANTINE RELIABLE BROADCAST")
                p = Process.Process()

            case "2":
                logging.info("MAIN:STARTING PROTOCOL--> AUTHENTICATED MESSAGES BROADCAST")
                p = Process_2.Process()

            case "3":
                logging.info("MAIN:STARTING PROTOCOL--> HASH BASED BROADCAST")
                p= Process_3.Process()

            case "4":
                logging.info("MAIN:STARTING PROTOCOL--> ERASURE CODE BASED BROADCAST")
                pass

            case _:
                print("Usage: python main.py <message to broadcast> <protocol number> <process type>: protocol number must be in this list[1,2,3,4]")
                exit(-1)
        
        p.connection_to_server()
        p.creation_links()
        # only the broadcaster will run this section of the code
        if (len(sys.argv)==4) and sys.argv[3]=='B':
            message = sys.argv[1]
            time.sleep(5)
            p.broadcast(message)
        exit(0)
        logging.info("MAIN:-----SUCCESSFULL EXIT-----")

    elif len(sys.argv) < 4:
        print("Usage: python main.py <message to broadcast> <protocol number> <process type>: too few arguments: 4 required:", len(sys.argv)-1,"given")
        exit(-1)

    elif not (sys.argv[3]=='R' or sys.argv[3]=='B'):
        print("Usage: python main.py <message to broadcast> <protocol number> <process type>: process type must be in this list[B,R]")
        exit(-1)
    else:
        print("Usage: python main.py <message to broadcast> <protocol number> <process type>: too many arguments: 4 required:", len(sys.argv)-1,"given")
        exit(-1)
