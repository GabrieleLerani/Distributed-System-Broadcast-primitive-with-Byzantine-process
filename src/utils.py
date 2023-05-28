import netifaces as ni
import logging
import os
import shutil
import csv
import string
import random
import signal
import time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def create_keys(n, path):
    with open(f"{path}/processes-info/symmetric_keys.csv", "w", newline="") as file:
        writer = csv.writer(file)

        keys = {}
        for i in range(1, n + 1):
            for j in range(1, n + 1):
                if (i, j) not in keys and (j, i) not in keys:
                    symm_key = ChaCha20Poly1305.generate_key().decode("latin1")
                    keys[(i, j)] = symm_key
                    writer.writerow([i, j, keys[i, j]])


# end app with signal SIGTERM
def end_app(pid, timer):
    time.sleep(timer)
    os.kill(pid, signal.SIGTERM)


# get ip of interface eth0 which each mininet host is listening
def get_ip_of_interface():
    interfaces = ni.interfaces()
    for interface in interfaces:
        if "eth0" in interface:
            return ni.ifaddresses(interface)[ni.AF_INET][0]["addr"]
    logging.error("PROCESS: No interface eth0")
    return -1


def set_process_logging(*args):
    filename = ""
    root = args[0]

    # set simple debug file for normal execution
    if len(args) == 1:
        filename = "{root}/execution-debug/debug{ip}.log".format(
            root=root, ip=get_ip_of_interface()
        )

    # set simulation folder for simulations execution
    else:
        payload_size = args[1]
        rnd = args[2]
        sim_num = args[3]
        filename = "{root}/simulations/payload_size{size}/round{round}/exec{sim_num}/debug_process{ip}.log".format(
            root=root,
            size=payload_size,
            sim_num=sim_num,
            round=rnd,
            ip=get_ip_of_interface(),
        )

    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename=filename,
        filemode="w",
        level=logging.DEBUG,
    )


def clean_debug_folder(root):
    path = f"{root}/execution-debug"
    for filename in os.listdir(path):
        file_path = os.path.join(path, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print("Failed to delete %s. Reason: %s" % (file_path, e))


def clean_simulation_folder(algorithms):

    for f in algorithms:
        file_list = os.listdir(f)
        if "simulations" not in file_list:
            path = os.path.join(f, "simulations")
            make_dir(path)

    for f in algorithms:
        for filename in os.listdir(f):
            

            if filename == "simulations":
                path = os.path.join(f, filename)
                for file_in_sim in os.listdir(path):
                    file_path = os.path.join(path, file_in_sim)

                    try:
                        if os.path.isfile(file_path) or os.path.islink(file_path):
                            os.unlink(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                    except Exception as e:
                        print("Failed to delete %s. Reason: %s" % (file_path, e))

                break
            
                

# create a directory if it doesn't exist
def make_dir(path):
    if not os.path.exists(path):
        os.mkdir(path)


def create_simulation_folders(algorithms, payload_sizes, num_procs, num_simulations):
    for algo in algorithms:
        for size in payload_sizes:
            payload_path = os.path.join(algo, "simulations", f"payload_size{size}")

            make_dir(payload_path)

            for proc in range(1, num_procs + 1):
                proc_path = os.path.join(payload_path, f"round{proc}")
                make_dir(proc_path)

                for sim in range(1, num_simulations + 1):
                    sim_path = os.path.join(proc_path, f"exec{sim}")
                    make_dir(sim_path)


# generate a random payload for a given length
def generate_payload(length):
    letters = string.ascii_lowercase
    result_str = "".join(random.choice(letters) for i in range(length))
    return result_str


# return process lists i.e. --> [[1,"10.0.0.1"], ... ,[n,"10.0.0.n"]]
def get_process_list(process_numbers):
    proc_list = []
    for i in range(1, process_numbers + 1):
        proc_list.append([i, "10.0.0.%i" % (i)])
    return proc_list


# write on file process ids and ips
def write_process_identifier(process_numbers, path):
    process_list = get_process_list(process_numbers)
    with open(f"{path}/processes-info/process_ids.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerows(process_list)
