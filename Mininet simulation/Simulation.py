#!/usr/bin/env python

import time
import utils
import sys
import Evaluation
import Topology

# TODO set the following as environment variable
SIMULATION_NUMBER = 2  # number of simulation for each number of process
SIMULATION_FREQUENCY = 3  # sec
MIN_PROC_NUMBER = 4
MAX_PROC_NUMBER = 8  # suggest to use only even numbers

payload_size = (512, 1024, 2048)
channel_bandwidth = ()


def setup_simulation_environment():
    # clean up folders
    utils.clean_simulation_folder()

    # set logging settings for simulation process
    utils.set_simulation_logging()

    # Create a folder for each simulation
    utils.create_simulation_folders(
        payload_size,
        int((MAX_PROC_NUMBER - MIN_PROC_NUMBER + 2) / 2),
        SIMULATION_NUMBER,
    )


def start_simulation():
    for size in payload_size:
        net = Topology.create_single_network(MIN_PROC_NUMBER)
        print("#### Single switch topology created\n")
        print(f"#### Running simulation for payload of {size} Bytes")

        for i in range(MIN_PROC_NUMBER, MAX_PROC_NUMBER + 1, 2):
            # write new identifiers according to the number of process
            utils.write_process_identifier(i)
            print(f"#### Running simulation round with {i} processes")
            if i != MIN_PROC_NUMBER:
                net = Topology.add_processes(net, 2)

            for j in range(SIMULATION_NUMBER):
                print(f"## Running simulation {j+1}")

                # TODO Modify with cycle to change payload size
                payload = utils.generate_payload(size)

                print()
                Topology.run_hosts(
                    net, size, int((i - MIN_PROC_NUMBER + 2) / 2), j + 1, payload
                )

                # timer used to allow hosts to terminate
                time.sleep(SIMULATION_FREQUENCY)

        time.sleep(2)
        Topology.free_space(net)
        time.sleep(5)
    print("")


if __name__ == "__main__":
    eval = Evaluation.Evaluation()
    setup_simulation_environment()
    start_simulation()

    # TODO Make performance evaluation with data collected during simulation process
    # eval.create_stats_file(simulations_number)
