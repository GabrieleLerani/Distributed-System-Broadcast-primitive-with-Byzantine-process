import math
import utils
import pika as pika
import AuthenticatedLink
import socket
import threading
from threading import Thread
import time
import json
import struct
import logging
import Evaluation


SERVER_ID = "10.0.0.1"
SERVER_PORT = 5026

RCV_BUFFER_SIZE = 1024
BREAK_TIME = 0.07


class Process:
    def __init__(self):
        self.ids = []
        self.ips = []
        self.currentMSG = []
        self.selfip = 0
        self.selfid = 0
        self.AL = []
        self.sentecho = False
        self.sentready = False
        self.delivered = False
        self.echos = {}
        self.readys = {}
        self.faulty = 0
        self.eval = Evaluation.Evaluation()

    def connection_to_server(self):
        # # It starts a connection to the server to obtain a port number
        # print(f"---{self.ids},{self.ips}")
        # print("-----CONNECTING TO SERVER...-----")
        # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        #     s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #     s.connect((SERVER_ID, SERVER_PORT))
        #     mess = bytes("Hello", "utf-8")
        #     s.sendall(mess)
        #     data = s.recv(RCV_BUFFER_SIZE).decode()

        #     logging.debug("PROCESS:This is the port given by the server: %s", data)
        # port = SERVER_PORT + int(data)

        # time.sleep(0.01)

        # print("-----CONNECTION TO SERVER SUCCESSFULLY CREATED-----")
        # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        #     sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        #     logging.info("CONNECTING TO SERVER FOR IPS LIST")
        #     sock.connect((SERVER_ID, port))
        #     mess = bytes("Hello", "utf-8")
        #     sock.sendall(mess)
        #     while True:
        #         #  the length prefix (4 bytes in network byte order)
        #         len_prefix = sock.recv(4)
        #         if not len_prefix:
        #             break

        #         # unpack the length prefix into an integer
        #         msg_len = struct.unpack("!I", len_prefix)[0]
        #         # receive the JSON object data
        #         json_data = b""
        #         while len(json_data) < msg_len:
        #             packet = sock.recv(msg_len - len(json_data))
        #             if not packet:
        #                 break
        #             json_data += packet

        #         # parse the JSON object
        #         obj = json.loads(json_data.decode("utf-8"))

        #         # Add IP and ID to list
        #         if isinstance(obj, dict):
        #             self.ids.append(obj.get("ID", "Not found"))
        #             self.ips.append(obj.get("IP", "Not found"))
        #         # END is str so isinstance of obj returns false
        #         else:
        #             break

        # logging.debug("PROCESS: id list: %s,ip list %s", self.ids, self.ips)
        # logging.info("PROCESS:Starting thread on function thread")
        # print("-----GATHERED ALL THE PEERS IPS FROM THE BOOTSTRAP SERVER-----")
        # print("-----STARTING SENDING OR RECEIVING MESSAGES-----")

        self.init_process_ids()

        logging.debug("PROCESS: id list: %s,ip list %s", self.ids, self.ips)
        print("-----GATHERED ALL THE PEERS IPS FROM THE BOOTSTRAP SERVER-----")
        print("-----STARTING SENDING OR RECEIVING MESSAGES-----")

        t = Thread(target=self.__thread)
        t.start()

    def init_process_ids(self):
        processes = utils.read_process_identifier()
        for pair in processes:
            self.ids.append(int(pair[0]))  # pair[0] --> ID
            self.ips.append(pair[1])  # pair[1] --> IPS

    # Without server is enough to make self.AL[i].receiver() once
    def creation_links(self):
        self.selfip = utils.get_ip_of_interface()
        self.selfid = self.ids[self.ips.index(self.selfip)]
        self.barrier = threading.Barrier(parties=2)

        for i in range(0, len(self.ids)):
            self.AL.append(
                AuthenticatedLink.AuthenticatedLink(
                    self.selfid,
                    self.selfip,
                    self.ids[i],
                    self.ips[i],
                    self,
                )
            )
            self.AL[i].receiver()

    def __thread(self):
        logging.info("PROCESS:Number of faulty processes is: %s", str(self.faulty))
        while True:
            for msg in self.currentMSG:
                counter_echos = 0
                counter_readys = 0

                for i in self.echos.values():
                    if i == msg:
                        counter_echos += 1
                for i in self.readys.values():
                    if i == msg:
                        counter_readys += 1

                if (
                    counter_echos > math.floor((len(self.ids) + self.faulty) / 2)
                ) and self.sentready is False:
                    self.sentready = True

                    logging.info("PROCESS:------ Starting ready part ------ ")
                    # Broadcast to all a ready message
                    for i in range(len(self.ids)):
                        if msg not in self.currentMSG:
                            self.currentMSG.append(msg)

                        self.AL[i].send(msg, flag="READY")

                if counter_readys > self.faulty and self.sentready is False:
                    self.sentready = True

                    # Broadcast to all a ready message
                    for i in range(len(self.ids)):
                        # TODO I don't know if it's an error
                        # self.currentMSG.append(msg)
                        if msg not in self.currentMSG:
                            self.currentMSG.append(msg)

                        self.AL[i].send(msg, flag="READY")

                if counter_readys > 2 * self.faulty and self.delivered is False:
                    self.delivered = True

                    logging.info("PROCESS: %d,%s", self.selfid, self.selfip)
                    logging.info(
                        "-----MESSAGE DELIVERED: %s, time: %s", msg, time.time()
                    )
                    if self.selfid == 1:
                        self.eval.check_time()

                    print("-----MESSAGE DELIVERED:", msg)

                    return

            # Not to destroy performance
            time.sleep(BREAK_TIME)

    # Before starting broadcast, a process reads the ip addresses and ids of
    # the other processes from its queue
    def update(self):
        with pika.BlockingConnection(
            pika.ConnectionParameters(host=SERVER_ID)
        ) as connection:
            channel = connection.channel()

            response = channel.queue_declare(queue=str(self.selfid))
            # Get the queue length (number of not consumed messages)
            num = response.method.message_count

            logging.info(
                "PROCESS: %d,%s --- My queue length: %d", self.selfid, self.selfip, num
            )

            if num == 0:
                channel.close()
                return

            self.counter = 0

            def callback(ch, method, properties, body):
                logging.info("PROCESS: [x] Received %r", body)
                queue_msg = body.decode("utf-8")
                temp = queue_msg.split("#")
                ip_from_queue = temp[0]
                id_from_queue = temp[1]
                if ip_from_queue not in self.ips:
                    self.ips.append(ip_from_queue)
                    self.ids.append(int(id_from_queue))
                    self.AL.append(
                        AuthenticatedLink.AuthenticatedLink(
                            self.selfid,
                            self.selfip,
                            self.ids[len(self.ids) - 1],
                            self.ips[len(self.ips) - 1],
                            self,
                        )
                    )
                    self.AL[len(self.AL) - 1].receiver()
                self.counter += 1
                if self.counter == num:
                    channel.stop_consuming()
                    channel.close()

            channel.basic_consume(
                queue=str(self.selfid), on_message_callback=callback, auto_ack=True
            )
            channel.start_consuming()

    # The message is sent using authenticated link abstractions, it's a string with a flag indicating
    # the type (SEND,ECHO,READY)
    def broadcast(self, message):
        # self.update()
        self.faulty = math.floor((len(self.ids) - 1) / 3)
        # for j in range(len(self.AL), len(self.ids)):
        #     self.AL.append(
        #         AuthenticatedLink.AuthenticatedLink(
        #             self.selfid, self.selfip, self.ids[j], self.ips[j], self
        #         )
        #     )
        #     self.AL[j].receiver()

        logging.info(
            "----- EVALUATION CHECKPOINT: broadcast start, time: %s -----", time.time()
        )
        self.eval.check_time()
        for i in range(len(self.ids)):
            if message not in self.currentMSG:
                self.currentMSG.append(message)
            self.AL[i].send(message, flag="SEND")
        self.barrier.wait()

    def deliver_send(self, msg, flag, idn):
        # id == 1 checks that the delivery is computed with the sender s that by convention it's the first

        if flag == "SEND" and idn == 1 and self.sentecho is False:
            # Add the message if it's not yet received
            if msg not in self.currentMSG:
                self.currentMSG.append(msg)
            self.sentecho = True
            if self.selfid == 1:
                self.barrier.wait()
            else:
                # self.update()  # If writer_id == 1 then it is correct, otherwise no
                self.faulty = math.floor((len(self.ids) - 1) / 3)
            logging.info(
                "PROCESS: %d,%s --- Starting the ECHO part...", self.selfid, self.selfip
            )

            for i in range(len(self.ids)):
                self.AL[i].send(msg, flag="ECHO")
        elif idn != 1:
            logging.info("PROCESS: %d is not the intended sender!", idn)

    def deliver_echo(self, msg, flag, idn):
        logging.info("PROCESS: Msg: %s, flag: %s, id: %d", msg, flag, idn)
        logging.info("PROCESS: CURRENTMSG %s", self.currentMSG)
        if flag == "ECHO" and idn not in self.echos:
            if msg not in self.currentMSG:
                self.currentMSG.append(msg)
            self.echos[idn] = msg

            logging.info("PROCESS: --------ECHOS VALUE: %s:", self.echos)

    def deliver_ready(self, msg, flag, idn):
        logging.info("PROCESS: Msg: %s, flag: %s, id: %d", msg, flag, idn)
        logging.info("PROCESS: CURRENTMSG %s", self.currentMSG)
        if flag == "READY" and idn not in self.readys:
            if msg not in self.currentMSG:
                self.currentMSG.append(msg)
            self.readys[idn] = msg

            logging.info("PROCESS: --------READYS VALUE: %s:", self.readys)
