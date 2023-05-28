import netifaces as ni
import logging
import os
import csv
import string
import random


def get_key(id_p1, id_p2):
    with open("BRACHA/processes-info/symmetric_keys.csv", "r", newline="") as file:
        reader = csv.reader(file)
        for row in reader:
            if (
                str(id_p1) == row[0]
                and str(id_p2) == row[1]
                or str(id_p1) == row[1]
                and str(id_p2) == row[0]
            ):
                return row[2].encode("latin-1")


# get ip of interface eth0 which each mininet host is listening
def get_ip_of_interface():
    interfaces = ni.interfaces()
    for interface in interfaces:
        if "eth0" in interface:
            return ni.ifaddresses(interface)[ni.AF_INET][0]["addr"]
    logging.error("PROCESS: No interface eth0")
    return -1


def read_process_identifier():
    process_list = []
    # change and create a folder for process_ids
    with open("BRACHA/processes-info/process_ids.csv", "r", newline="") as file:
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


# generate a random payload for a given length
def generate_payload(length):
    letters = string.ascii_lowercase
    result_str = "".join(random.choice(letters) for i in range(length))
    return result_str
