#!/usr/bin/env python

import time
import utils
import sys
import Evaluation
import Topology

SIMULATION_FREQUENCY = 5


def setup_simulation_environment(simulation_number, processes_number):
    # clean up folders
    utils.clean_simulation_folder()

    # set logging settings for simulation process
    utils.set_simulation_logging()

    # Create a folder for each simulation
    utils.create_simulation_folders(simulation_number)

    # Write the pair (id,ip) of each process on file
    utils.write_process_identifier(processes_number)


def start_simulation(simulations_number, hosts):
    for i in range(simulations_number):
        print(f"Running simulation {i+1}")
        Topology.run_hosts(net, hosts, i + 1)

        # timer used to allow hosts to terminate
        time.sleep(SIMULATION_FREQUENCY)


if __name__ == "__main__":
    # TODO insert some print to check flow
    if len(sys.argv) > 3:
        print("Usage: python Simulation.py <processes number> <simulations number>")
        exit(-1)

    elif len(sys.argv) == 3:
        processes_number = int(sys.argv[1])  # Number of simulated host in the system
        simulations_number = int(sys.argv[2])  # Number of simulation to execute

        # Clean debug folder and write processes identifier on file
        # in such a way all processes know each other
        eval = Evaluation.Evaluation(processes_number, simulations_number)
        setup_simulation_environment(simulations_number, processes_number)

        # Create a linear topology network with N hosts and N switches
        net, hosts = Topology.create_linear_network(processes_number)
        # net, hosts = Topology.create_single_network(processes_number)

        # Run N rounds of simulation
        start_simulation(simulations_number, hosts)

        # Clean up simulated network TODO
        Topology.free_space(net)

        # Make performance evaluation with data collected during simulation process
        eval.create_stats_file(simulations_number)
