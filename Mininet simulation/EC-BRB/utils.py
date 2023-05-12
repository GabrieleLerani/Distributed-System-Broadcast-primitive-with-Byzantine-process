import json
import struct
import netifaces as ni
import logging
import os
import signal
import shutil
import csv
import string
import random
import time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


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


def create_keys(n):
    with open("symmetric_keys.csv", "w", newline="") as file:
        writer = csv.writer(file)

        keys = {}
        for i in range(1, n + 1):
            for j in range(1, n + 1):
                if (i, j) not in keys and (j, i) not in keys:
                    symm_key = ChaCha20Poly1305.generate_key().decode("latin1")
                    keys[(i, j)] = symm_key
                    writer.writerow([i, j, keys[i, j]])


def get_key(id_p1, id_p2):
    with open("symmetric_keys.csv", "r", newline="") as file:
        reader = csv.reader(file)
        for row in reader:
            if (
                str(id_p1) == row[0]
                and str(id_p2) == row[1]
                or str(id_p1) == row[1]
                and str(id_p2) == row[0]
            ):
                return row[2].encode("latin-1")


def end_app(pid, timer):
    time.sleep(timer)
    os.kill(pid, signal.SIGTERM)


def serialize_json(message):
    # serialize
    json_serialized = json.dumps(message)

    # get the length of serialized JSON
    json_len = len(json_serialized)

    # pack the length as a 4-byte unsigned integer in network byte standard order
    header = struct.pack("!I", json_len)

    # concatenate header and serialized JSON
    payload = header + json_serialized.encode("utf-8")

    return payload


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


def set_process_logging(payload_size, rnd, sim_num):
    logging.getLogger("pika").setLevel(logging.WARNING)

    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        # TODO uncomment for simulations
        filename="debug/debug.process{ip}.log".format(ip=get_ip_of_interface()),
        # filename="simulations/payload_size{size}/round{round}/exec{sim_num}/debug_process{ip}.log".format(
        #    size=payload_size, sim_num=sim_num, round=rnd, ip=get_ip_of_interface()
        # ),
        filemode="w",
        level=logging.DEBUG,
    )


def set_server_logging():
    clean_simulation_folder()
    logging.getLogger("pika").setLevel(logging.WARNING)
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename="debug/debug_server.log",
        filemode="w",
        level=logging.DEBUG,
    )


def clean_simulation_folder():
    # TODO statistics shouldn't be removed
    folder = ["simulations", "debug", "statistics"]
    for f in folder:
        for filename in os.listdir(f):
            file_path = os.path.join(f, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print("Failed to delete %s. Reason: %s" % (file_path, e))


def write_process_identifier(process_numbers):
    process_list = get_process_list(process_numbers)
    with open("process_ids.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerows(process_list)


def read_process_identifier():
    process_list = []
    # change and create a folder for process_ids
    with open("process_ids.csv", "r", newline="") as file:
        reader = csv.reader(file)
        for row in reader:
            process_list.append(row)

    return process_list


def get_process_list(process_numbers):
    proc_list = []
    for i in range(1, process_numbers + 1):
        proc_list.append(
            [process_numbers + 1 - i, "10.0.0.%i" % (i)]
        )  # first process in mininet has 10.0.0.2 beacause nat is 10.0.0.1

    return proc_list


def make_dir(path):
    if not os.path.exists(path):
        os.mkdir(path)


def create_simulation_folders(payload_sizes, num_procs, num_simulations):
    for size in payload_sizes:
        payload_path = f"simulations/payload_size{size}"
        make_dir(payload_path)

        for proc in range(1, num_procs + 1):
            proc_path = f"{payload_path}/round{proc}"
            make_dir(proc_path)

            for sim in range(1, num_simulations + 1):
                sim_path = f"{proc_path}/exec{sim}"
                make_dir(sim_path)


# generate a random payload of a given size
def generate_payload(length):
    letters = string.ascii_lowercase
    result_str = "".join(random.choice(letters) for i in range(length))
    return result_str


# TODO remove, used for debugging
if __name__ == "__main__":
    clean_simulation_folder()
    write_process_identifier(4)
