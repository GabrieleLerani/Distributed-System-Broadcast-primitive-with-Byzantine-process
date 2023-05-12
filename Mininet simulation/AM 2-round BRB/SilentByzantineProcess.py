import math
import Link
import utils
import socket
from threading import Thread
import json
import time
import logging
from sys import platform
from hashlib import sha512
import Authenticated_Link
import Evaluation
import Process


KDS_IP = "10.0.0.1"
KDS_PORT = 8080

RCV_BUFFER_SIZE = 32768
BREAK_TIME = 0.1

BROADCASTER_ID = 1

PLACEHOLDER = "vote_msg"


class SilentProcess(Process):
    def process_receive(self, message):
        match message.get("TYPE"):
            case 0:
                print("The PROPOSE message received was <", message, ">")

            case 1:
                print("The VOTE message received was <", message, ">")

            case 2:
                temp_l = message["SIGNED_VOTE_MSGS"]
                print("These are the n - f forwarded messages received: ")
                for i in range(len(temp_l)):
                    print("Number ", i, " -> ", temp_l[i])

            case _:
                print("This is the undefined message received:")
                print(message)
