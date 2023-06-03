# import bracha algorithm
from BRACHA.Process import Process as Bracha
from BRACHA.byzantine.SilentByzantineProcess import ByzantineProcess as BRACHASilentByzantine
from BRACHA.byzantine.ByzantineProcess import ByzantineProcess as BRACHAByzantineProcess

# import AM with 2 round
from AM.Process import Process as AuthenticatedMessages

# import erasure code algorithm and byzantine
from EC.Process import Process as ErasureCode
from EC.byzantine.ByzantineProcess import ByzantineProcess as ECByzantineProcess
from EC.byzantine.SilentByzantineProcess import ByzantineProcess as ECSilentByzantine
from EC.byzantine.ByzantineSender import ByzantineProcess as ECSenderByzantineProcess

# import hash based algorithm and byzantine
from HB.Process import Process as HashBased
from HB.byzantine.ByzantineProcess import ByzantineProcess as HBByzantineProcess
from HB.byzantine.SilentByzantineProcess import ByzantineProcess as HBSilentByzantine
from HB.byzantine.ByzantineSender import ByzantineProcess as HBSenderByzantineProcess


# import other useful module
import os
import time
import time
import argparse
import utils as MainUtils

EXECUTION_TIME_BEFORE_BROADCAST = 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
        Broadcast algorithms with fault-byzantine processes.
        If you are a broadcaster, specify the following command inside a mininet host.
        It must be the first host in the network (i.e., the one with 10.0.0.1 as IP):
        
        python BRB.py --type N --number 4 --algorithm BRACHA --broadcaster.
        
        After executing this command, you will be prompted to enter a message to send.
        Then, you have to start the other 3 mininet hosts (as above, they must be sequential,
        i.e., with 4 hosts, you must run the broadcaster on the host with IP 10.0.0.1 and
        the other 3 processes on 10.0.0.2, 10.0.0.3, 10.0.0.4). On each host, type:
        
        python BRB.py --type N --algorithm BRACHA.

        Notice that when you run AM algorithm you must provide ip address of the KDS, 
        therefore in mininet you have to run N + 1 host: as an instance, with 4 processes
        you need 5 mininet host, 4 for processes (as above you must use 10.0.0.1 as broadcaster and other 
        as receivers) and 1 for KDS, by convention Key Distribution Center runs in the last host 
        (10.0.0.5 in this case). To run KDS you have to move inside Algorithms Simulation/AM/ path and type:

        python KDSMain.py -t N.

        Then open the first mininet host to execute broadcaster, go inside Algorithms Simulation folder and type:

        python BRB.py --type N --number 4 --algorithm AM --broadcaster --kds 10.0.0.5 .

        To run other 3 processes type:

        python BRB.py --type N --algorithm AM --kds 10.0.0.5

        It's also recommended to restart KDS for each algorithm execution.
        
    """
    )

    # Normal execution arguments
    parser.add_argument(
        "-t",
        "--type",
        choices=["N", "S"],
        help="N stays for normal execution and S for simulation execution, notice that normal is used when you want to try the application, otherwise simulation execution is used by Simulation.py script and it must not be used by a normal user, it's just a way to automatically initialize process tasks",
    )
    parser.add_argument(
        "-a",
        "--algorithm",
        required=True,
        choices=["BRACHA", "AM", "HB", "EC"],
        help="defines broadcast algorithms, BRACHA indicates double echo algorithm with authenticated links, AM is broadcast algorithm which uses authenticated messages with digital signatures, HB is an hash based broadcast algorithm which allow to have fixed size message, EC is similar to an hash based but it uses an MDS erasure code to reconstruct the original message",
    )
    parser.add_argument(
        "-b",
        "--broadcaster",
        action="store_true",
        help="defines if you are broadcaster or not",
    )

    parser.add_argument(
        "-f",
        "--faulty",
        choices=["SILENT","FORGER","SENDER",],
        help="defines if you want to act as a byzantine or not. SILENT is a process who receives message but doesn't replay nothing, FORGER replays different messages from the one received and SENDER is used to allow broadcaster to send more than two messages ",
    )

    parser.add_argument(
        "-n",
        "--number",
        type=int,
        help="number of processes, it must be specified only by broadcaster",
    )

    parser.add_argument(
        "-k",
        "--kds",
        type=str,
        help="key distribution center and you must type its ip, only for AM algorithm. It allows process to exchange key pairs",
    )

    parser.add_argument(
        "-p",
        "--payloadsize",
        type=int,
        choices=[256, 512, 1024, 2048, 4096],
        help="payload size (only for simulation execution)",
    )
    parser.add_argument(
        "-r",
        "--round",
        type=int,
        help="defines round for process simulation (only for simulation execution)",
    )
    parser.add_argument(
        "-s",
        "--simulation",
        type=int,
        help="defines number of simulation for each process number (only for simulation execution)",
    )

    # Parse the command-line arguments
    args = parser.parse_args()

    # Display help if no arguments or options are provided
    if not any(vars(args).values()):
        parser.print_help()
        parser.exit()

    # BRB-algorithm you want to use
    algo = args.algorithm

    # Access the values of the command-line options
    mode = args.type
    # normal mode used to test by user
    if mode == "N":
        n = args.number  # number of process
        folder = ""  # folder of algorithm
        p = None  # Type of process to use

        end_time = 20
        match algo:
            case "BRACHA":
                
                folder = "BRACHA"
                if args.faulty == "SILENT":
                    p = BRACHASilentByzantine()
                elif args.faulty == "FORGER":
                    p = BRACHAByzantineProcess()
                else:
                    p = Bracha()

            case "AM":
                kds_ip = args.kds
                # in case of AM you need to specify kds to connect with
                if not kds_ip:
                    print(
                        "Error: --kds is required for AM, you need to specify kds's ip, type --help for more instructions"
                    )
                    parser.exit()

                end_time = 40
                folder = "AM"
                p = AuthenticatedMessages(kds_ip)

            case "HB":
                folder = "HB"
                if args.faulty == "SILENT":
                    p = HBSilentByzantine()
                elif args.faulty == "FORGER":
                    p = HBByzantineProcess()
                elif args.faulty == "SENDER":
                    p = HBSenderByzantineProcess()
                    
                else:
                    p = HashBased()

            case "EC":
                folder = "EC"
                if args.faulty == "SILENT":
                    p = ECSilentByzantine()
                elif args.faulty == "FORGER":
                    p = ECByzantineProcess()
                elif args.faulty == "SENDER":
                    p = ECSenderByzantineProcess()

                else:
                    p = ErasureCode()
                

        # process is broadcaster
        if args.broadcaster:
            # in case of AM first process to be executed is KDS, thus it has to clean
            # debug folder
            if algo != "AM":
                # clean up debug folder
                MainUtils.clean_debug_folder(folder)

            # set process logging path
            MainUtils.set_process_logging(folder)

            # check whether number of process is valid
            if not n or n < 4:
                print(
                    "Error: --number is required when you are broadcaster and it must be at least 4, type --help for instructions"
                )
                print("Usage example: python BRB.py -t N -a BRACHA -n 4 --broadcaster")
                parser.exit()

            # broadcaster creates process ids
            MainUtils.write_process_identifier(n, folder)

            # broadcaster creates keys for authenticated links
            MainUtils.create_keys(n, folder)

            # Init processes ids
            p.init_process()

            # Create connection links among processes
            p.creation_links()

            # Start broadcast
            p.broadcast()

            # End application, this is used to have all processes end at the same time
            MainUtils.end_app(os.getpid(), end_time)

        # process is not broadcaster
        else:
            # set process logging path
            MainUtils.set_process_logging(folder)

            # Init processes ids
            p.init_process()

            # Create connection links among processes
            p.creation_links()

            # End application, this is used to have all processes end at the same time
            MainUtils.end_app(os.getpid(), end_time + 5)

    # simulation used by Simulation.py script, not used by user
    elif mode == "S":
        # defines simulation paramater to setup folder
        payload_size = args.payloadsize
        round = args.round
        simulation = args.simulation
        broadcaster = args.broadcaster

        p = None
        folder = ""
        end_time = 4
        match algo:
            case "BRACHA":
                folder = "BRACHA"
                if args.faulty == "SILENT":
                    p = BRACHASilentByzantine()
                elif args.faulty == "FORGER":
                    p = BRACHAByzantineProcess()
                else:
                    p = Bracha()

            case "AM":
                folder = "AM"
                kds_ip = args.kds
                # in case of AM you need to specify kds to connect with
                if not kds_ip:
                    print(
                        "Error: --kds is required for AM, you need to specify kds's ip, type --help for more instructions"
                    )
                    parser.exit()

                if args.faulty:
                    pass
                end_time = 2 * end_time
                p = AuthenticatedMessages(kds_ip)

            case "HB":
                folder = "HB"
                if args.faulty == "SILENT":
                    p = HBSilentByzantine()
                elif args.faulty == "FORGER":
                    p = HBByzantineProcess()
                elif args.faulty == "SENDER":
                    p = HBSenderByzantineProcess()
                    
                else:
                    p = HashBased()

            case "EC":
                folder = "EC"
                if args.faulty == "SILENT":
                    p = ECSilentByzantine()
                elif args.faulty == "FORGER":
                    p = ECByzantineProcess()
                elif args.faulty == "SENDER":
                    p = ECSenderByzantineProcess()

                else:
                    p = ErasureCode()

        MainUtils.set_process_logging(folder, payload_size, round, simulation)

        # Init processes ids
        p.init_process()

        # Create connection links among processes
        p.creation_links()

        if broadcaster and payload_size and round and simulation:
            # Timer is used to allow other processes to start and initialize connections between them
            time.sleep(EXECUTION_TIME_BEFORE_BROADCAST)

            # Start broadcast
            p.broadcast(payload_size)

            # Wait before closing the application
            MainUtils.end_app(os.getpid(), end_time)

        else:
            # Wait before closing the application
            MainUtils.end_app(os.getpid(), end_time + 0.7)

    else:
        parser.print_help()
        parser.exit()
