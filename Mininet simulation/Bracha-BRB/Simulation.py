#!/usr/bin/env python

import time
import utils
import sys
import Evaluation
import Topology
import resource

# TODO set the following as environment variable or with YAML file
SIMULATION_NUMBER = 2  # number of simulation for each number of process
SIMULATION_FREQUENCY = 4  # sec
MIN_PROC_NUMBER = 4
MAX_PROC_NUMBER = 8  # suggest to use only even numbers

payload_size = (256, 512, 1024, 2048)


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

                
                Topology.run_hosts(
                    net, size, int((i - MIN_PROC_NUMBER + 2) / 2), j + 1, payload
                )

                # TODO timer used to allow hosts to terminate
                time.sleep(SIMULATION_FREQUENCY)

        # TODO used to reduce CPU utilization
        time.sleep(3)
        Topology.free_space(net)
        time.sleep(5)
    print("#### Resources removed")


if __name__ == "__main__":
    eval = Evaluation.Evaluation(
        payload_size,
        int((MAX_PROC_NUMBER - MIN_PROC_NUMBER + 2) / 2),
        SIMULATION_NUMBER,
    )

    setup_simulation_environment()
    start_simulation()
    eval.create_stats_file()
    eval.plot_graphs()
