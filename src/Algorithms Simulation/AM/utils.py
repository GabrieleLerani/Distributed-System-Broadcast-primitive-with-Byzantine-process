import json
import netifaces as ni
import logging
import os
import shutil
import csv
import string
import random
import signal
import time
import re


def get_key(id_p1, id_p2):
    with open("AM/processes-info/symmetric_keys.csv", "r", newline="") as file:
        reader = csv.reader(file)
        for row in reader:
            if (
                str(id_p1) == row[0]
                and str(id_p2) == row[1]
                or str(id_p1) == row[1]
                and str(id_p2) == row[0]
            ):
                return row[2].encode("latin-1")


def count_dictionaries(data):
    decoded_data = data.decode()
    pattern = r"{[^{}]*}"
    matches = re.findall(pattern, decoded_data)
    return len(matches)


def end_app(pid, timer):
    time.sleep(timer)
    os.kill(pid, signal.SIGTERM)


def decode_json(data):
    decoder = json.JSONDecoder()
    pos = 0
    while True:
        try:
            obj, pos = decoder.raw_decode(data, pos)
        except json.JSONDecodeError as e:
            print("Error: ", e)
            return None
        yield obj
        if pos == len(data):
            break


# get ip of interface eth0 which each mininet host is listening
def get_ip_of_interface():
    interfaces = ni.interfaces()
    for interface in interfaces:
        if "eth0" in interface:
            return ni.ifaddresses(interface)[ni.AF_INET][0]["addr"]
    logging.error("PROCESS: No interface eth0")
    return -1


def set_simulation_logging():
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename="debug/debug_simulation.log",
        filemode="w",
        level=logging.DEBUG,
    )


def clean_debug_folder():
    path = "execution-debug"
    for filename in os.listdir(path):
        file_path = os.path.join(path, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print("Failed to delete %s. Reason: %s" % (file_path, e))


def read_process_identifier():
    process_list = []
    # change and create a folder for process_ids
    with open("AM/processes-info/process_ids.csv", "r", newline="") as file:
        reader = csv.reader(file)
        for row in reader:
            process_list.append(row)

    return process_list


def get_process_list(process_numbers):
    proc_list = []
    for i in range(1, process_numbers + 1):
        proc_list.append([i, "10.0.0.%i" % (i)])

    return proc_list


def make_dir(path):
    if not os.path.exists(path):
        os.mkdir(path)


# generate a random payload of a given size
def generate_payload(length):
    letters = string.ascii_lowercase
    result_str = "".join(random.choice(letters) for i in range(length))
    return result_str
