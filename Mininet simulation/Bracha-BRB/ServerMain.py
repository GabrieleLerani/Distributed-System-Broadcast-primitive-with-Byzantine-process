from threading import Thread
import utils
import Server
import time


def run_server_thread():
    server = Server.TCP_SERVER()
    server.do_get()
    # time.sleep(10)
    # server.delete_queues()
    # return
    # server.get_id_from_queue_file()


if __name__ == "__main__":
    utils.set_server_logging()

    t = Thread(
        target=run_server_thread,
    )
    t.start()
    exit(0)
