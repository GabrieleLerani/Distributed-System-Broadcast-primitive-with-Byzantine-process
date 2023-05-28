#!/usr/bin/env python

import time
import utils
import Evaluation
import Topology


# TODO set the following as environment variable or with YAML file
SIMULATION_NUMBER = 5  # number of simulation for each number of process
SIMULATION_FREQUENCY = 2  # frequency of simulation in second
MIN_PROC_NUMBER = 4  # minimum number of process to run simulation, must be even
MAX_PROC_NUMBER = 14  # maximum number of process to run simulation, must be even

# payload_size = (256, 512, 1024, 2048)
payload_size = (2048, 1024, 512, 256)


def setup_simulation_environment():
    # clean up folders
    utils.clean_simulation_folder()

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
            utils.create_keys(i)
            print(f"#### Running simulation round with {i} processes")
            if i != MIN_PROC_NUMBER:
                # add two new processes to topology
                net = Topology.add_processes(net, 2)

            # starts new simulation
            for j in range(SIMULATION_NUMBER):
                print(f"## Running simulation {j+1}")

                payload = utils.generate_payload(size)
                round = int((i - MIN_PROC_NUMBER + 2) / 2)
                sim_number = j + 1

                Topology.run_hosts(net, size, round, sim_number, payload)

                # time.sleep(SIMULATION_FREQUENCY)
            # time.sleep(1)

        Topology.free_space(net)
        # time.sleep(1)
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
