import json
import struct
import netifaces as ni
import logging
import os
import shutil
import csv


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


def set_process_logging(sim_num):
    logging.getLogger("pika").setLevel(logging.WARNING)

    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename="simulations/sim{sim_num}/debug_process{ip}.log".format(
            ip=get_ip_of_interface(), sim_num=sim_num
        ),
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


def create_simulation_folders(N):
    for i in range(N):
        print(f"Creating folder sim{i + 1}")
        os.mkdir("simulations/sim%i" % (i + 1))


# TODO remove, used for debugging
if __name__ == "__main__":
    clean_simulation_folder()
    create_simulation_folders(3)
    write_process_identifier(3)
    # read_process_identifier()
