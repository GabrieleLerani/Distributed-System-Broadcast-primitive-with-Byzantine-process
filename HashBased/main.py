import time
import Process

TIME_SLEEP = 10


Role = "Broadcaster"
#Role = "Receiver"

if __name__ == '__main__':
    p = Process.Process()
    p.connection_to_server()
    p.creation_links()
    if Role == "Broadcaster":
        time.sleep(TIME_SLEEP)
        p.broadcast("Hello!")
    exit(0)