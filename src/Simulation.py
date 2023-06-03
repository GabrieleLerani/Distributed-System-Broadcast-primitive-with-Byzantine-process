#!/usr/bin/env python
import utils
import Evaluation
import Topology


SIMULATION_NUMBER = 10  # number of simulation for each number of process
MIN_PROC_NUMBER = 20  # minimum number of process to run simulation, must be even
MAX_PROC_NUMBER = 20  # maximum number of process to run simulation, must be even

payload_size = (2048, 1024, 512, 256)
algorithms = ("EC","HB","BRACHA")


def setup_simulation_environment():
    # clean up folders
    utils.clean_simulation_folder(algorithms)

    # Create a folder for each simulation
    utils.create_simulation_folders(
        algorithms,
        payload_size,
        int((MAX_PROC_NUMBER - MIN_PROC_NUMBER + 2) / 2),
        SIMULATION_NUMBER,
    )


def start_simulation():
    
    get_faulty = str(input("Do you want to execute simulation with (n - 1)/3 byzantine processes? [Y/n] "))
    faulty_simulations = get_faulty == "Y"
        

    for algo in algorithms:
        print(f"----------- SIMULATION FOR {algo} -----------")
        for size in payload_size:
            net = Topology.create_single_network(MIN_PROC_NUMBER)

            print("#### Single switch topology created")
            print(f"#### Running simulation for payload of {size} Bytes")

            for i in range(MIN_PROC_NUMBER, MAX_PROC_NUMBER + 1, 2):
                # write new identifiers according to the number of process
                utils.write_process_identifier(i, algo)

                # create cryptographic keys for authenticated links
                utils.create_keys(i, algo)
                print(f"#### Running simulation round with {i} processes")

                if i != MIN_PROC_NUMBER:
                    # add two new processes to topology
                    net = Topology.add_processes(net, 2)

                # starts new simulation
                for j in range(SIMULATION_NUMBER):
                    print(f"## Running simulation {j+1}")

                    round = int((i - MIN_PROC_NUMBER + 2) / 2)
                    sim_number = j + 1

                    Topology.run_hosts(
                        net,
                        algo,
                        size,
                        round,
                        sim_number,
                        2 * MAX_PROC_NUMBER + i + j,  # KDS ip
                        faulty_simulations,
                    )

            Topology.free_space(net)

        print("#### Resources removed")


if __name__ == "__main__":
    # creat an evaluation object
    eval = Evaluation.Evaluation(
        payload_size,
        int((MAX_PROC_NUMBER - MIN_PROC_NUMBER + 2) / 2),
        SIMULATION_NUMBER,
        algorithms,
    )

    # setup simulation, create folders
    setup_simulation_environment()

    # run simulation with mininet
    start_simulation()

    if not eval.there_is_stats():
        # create statistics file
        eval.create_stats_file()

    # show graphics
    eval.plot_all()