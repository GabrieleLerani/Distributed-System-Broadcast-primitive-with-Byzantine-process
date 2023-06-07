import warnings

# Ignore all DeprecationWarning
warnings.filterwarnings("ignore", category=DeprecationWarning)

import logging
import KDS
import asyncore
import utils
import os
import argparse
from threading import Thread

PORT = 8081


def thread_KDS(ip):
    print(f"Key distribution server running on {ip} port {PORT}")
    print("Handling for request...")
    asyncore.loop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Key Distribution Center application")

    # Normal execution arguments
    parser.add_argument(
        "-t",
        "--type",
        choices=["N"],
        required=True,
        help="N stays for normal execution, you have to specify if you are trying AM protocls ",
    )

    # Parse the command-line arguments
    args = parser.parse_args()

    end_time = 15
    if args.type:
        end_time = 50

    utils.clean_debug_folder()
    # dummy main for starting servers
    logging.basicConfig(
        filename="execution-debug/KDS.log", filemode="w", level=logging.INFO
    )

    # initializing servers
    ip = utils.get_ip_of_interface()
    server = KDS.KDSServer(ip, PORT)
    # starting servers
    t = Thread(target=thread_KDS, args=(ip,))
    t.start()
    utils.end_app(os.getpid(), end_time)
