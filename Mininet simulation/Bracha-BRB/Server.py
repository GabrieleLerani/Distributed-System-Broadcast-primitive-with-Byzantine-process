import socket
from threading import Thread
import pika
import utils
import logging
import time
import threading

SERVER_PORT = 5026
RCV_BUFFER_SIZE = 1024
LISTEN = 100
TIMER = 25  # After this timer all queues are deleted


class TCP_SERVER:
    def __init__(self):
        self.N = 10
        self.IDS = []
        self.IPS = []
        self.IDS_size = 0
        self.IPS_size = 0
        self.t = 0
        self.current_IP = None
        self.IP = None
        self.PORT = SERVER_PORT

        self.queues_to_remove = False  # TODO
        self.number_of_runs = 0  # TODO improve with writing on file

    def do_get(self):
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.IP = utils.get_ip_of_interface()

        server_address = (self.IP, self.PORT)

        logging.info(" SERVER: starting up on %s port %s" % server_address)
        # TODO
        logging.info("#### INITIAL-LIST %s" % self.IDS)

        # Bind the socket to the port
        sock.bind(server_address)

        # Listen for incoming connections
        sock.listen(LISTEN)

        t = Thread(target=self.start_counter, args=(TIMER,))
        t.start()

        while True:
            # Wait for a connection from a process

            logging.info("SERVER: waiting for a connection")
            connection, client_address = sock.accept()

            # Clean up queues
            if self.queues_to_remove and self.number_of_runs > 0:
                ids = self.get_id_from_queue_file()
                self.delete_queues(ids)

            with connection:
                print(f"Connection opened: {client_address}")
                logging.debug("SERVER: connection from %s", client_address)

                # Receive the data in small chunks and retransmit it
                while True:
                    # first hello message
                    data = connection.recv(RCV_BUFFER_SIZE)

                    logging.debug('SERVER: received "%s"', data)
                    if data:
                        logging.debug("SERVER: sending data back to the client")
                        # advertising the peers of a new peer
                        # sending back to client process the address of the socket's thread
                        # updating global information
                        if client_address[0] not in self.IPS:
                            self.IDS_size += 1
                            for p_id in range(1, self.IDS_size + 1):
                                self.write_queue_id(p_id)

                                t = Thread(
                                    target=self.thread_trigger,
                                    args=(client_address, p_id),
                                )
                                t.start()
                            self.IPS.append(client_address[0])
                            self.IPS_size += 1

                            self.IDS.append(self.IDS_size)
                        self.t += 1
                        # creating thread

                        t = Thread(
                            target=self.thread_conn,
                            args=(
                                self.t,
                                client_address,
                            ),
                        )

                        logging.info("RUNNING THREAD IN SERVER")
                        t.start()
                        # sending information

                        connection.sendall(bytes(str(self.t), "utf-8"))

                    else:
                        logging.debug("SERVER: no more data from %s", client_address)
                        break

    def thread_conn(self, t, c_address):
        # Create a TCP/IP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Bind the socket to the port
            server_address = (self.IP, self.PORT + t)
            print(f"I'm opening a socket on {server_address}")

            logging.debug(
                " THREAD_CONN: starting up on %s port %s",
                server_address[0],
                server_address[1],
            )

            sock.bind(server_address)
            # Listen for incoming connections
            sock.listen(0)

            while True:
                # Wait for a connection from a process

                logging.debug("THREAD_CONN: waiting for a connection")
                connection, client_address = sock.accept()

                with connection:
                    logging.debug("THREAD_CONN: connection from %s", client_address)

                    # Receive the data in small chunks and retransmit it
                    while True:
                        # second hello message
                        data = connection.recv(RCV_BUFFER_SIZE)

                        if data:
                            logging.debug("THREAD_CONN: received %s", data)

                            logging.debug(
                                "THREAD_CONN: sending data back to the client"
                            )
                            # sending back to client process the address of the socket's thread
                            # creating dictionary for the process
                            # print("THREAD_CONN: sending dictionaries of ips list:", self.IPS)
                            logging.debug(
                                "THREAD_CONN: sending dictionaries of ips list: %s",
                                self.IPS,
                            )

                            for i in range(self.IDS_size):
                                if self.IPS[i] != c_address:
                                    proc_dict = {"IP": self.IPS[i], "ID": self.IDS[i]}
                                    payload = utils.serialize_json(proc_dict)
                                    connection.sendall(payload)

                            end_message = utils.serialize_json("END")
                            connection.sendall(end_message)

                            logging.info(
                                "THREAD_CONN: dictionaries of ips list sent successfully"
                            )

                        else:
                            logging.debug(
                                "THREAD_CONN: no more data from %s", client_address
                            )
                            break

    def thread_trigger(self, c_address, queue_id):
        # creating queue
        logging.debug("THREAD_QUEUE: creating queue for %s", c_address)
        try:
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=self.IP)
            )  # Connect to CloudAMQP

            try:
                channel = connection.channel()  # start a channel
                channel.queue_declare(queue=str(queue_id))  # naming queue
                channel.basic_publish(
                    exchange="",
                    routing_key=str(queue_id),
                    body=bytes(str(c_address[0]) + "#" + str(self.IDS_size), "utf-8"),
                )
            finally:
                connection.close()  # closing connection
                # self.write_queue_id(queue_id)
                logging.debug(
                    "THREAD_QUEUE: closing queue's connection for %s", c_address
                )

        except Exception as e:
            logging.error(e)

    def delete_queues(self, queue_ids):
        print("Deleting queues")
        try:
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=self.IP)
            )
            try:
                channel = connection.channel()  # start a channel
                for id in queue_ids:
                    logging.debug("REMOVING QUEUES: closing queue %d", id)
                    channel.queue_delete(queue=str(id))
            finally:
                connection.close()

        except Exception as e:
            logging.error(e)

    def on_timeout(self):
        self.queues_to_remove = True
        self.number_of_runs += 1
        self.delete_queues(self.IDS)
        print("Timeout!")

    def start_counter(self, timeout):
        print("Counter() starts!")
        totalSleepTime = 0
        while self.queues_to_remove is False:
            totalSleepTime = totalSleepTime + 1
            time.sleep(1)
            if totalSleepTime == timeout:
                self.on_timeout()

    def write_queue_id(self, queue_id):
        with open("debug/queues_id.txt", "a") as file:
            print("Writing id", queue_id)
            file.write(str(queue_id) + "-")

    def get_id_from_queue_file(self):
        with open("debug/queues_id.txt", "r") as file:
            line = file.readlines()[0]

            temp1 = line.split("-")
            temp2 = temp1[: len(temp1) - 1]
            temp2.reverse()

            all_ids_to_int = list(map(int, temp2))

            queue_ids = []

            for elem in all_ids_to_int:
                if elem == "1":
                    queue_ids.append(elem)
                    break
                queue_ids.append(elem)
            return queue_ids
