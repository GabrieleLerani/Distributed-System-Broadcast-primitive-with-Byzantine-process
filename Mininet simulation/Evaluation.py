import time
import tracemalloc
import csv
import os
import re
import numpy as np
import pandas as pd


class Evaluation:
    def __init__(self):
        self.start = 0
        self.end = 0
        self.snap = []

    def check_time(self):
        if self.start != 0:
            self.end = time.time()
            execution_time = self.end - self.start
            self.end = 0
            print(f"{execution_time} ms")
        self.start = time.time()

    def start_check_resources(self):
        tracemalloc.start()

    def take_snapshot(self, flag):
        self.snap.append([tracemalloc.take_snapshot(), flag])

    def snap_diff(self):
        compare = self.snap[len(self.snap) - 1].compare_to(
            self.snap[len(self.snap) - 2], "lineno", False
        )
        for i in compare:
            print(i)

    def stats(self):
        stats = self.snap[len(self.snap) - 1].statistics()
        for i in stats:
            print(i)

    def memory_used(self):
        size, peak = tracemalloc.get_tracemalloc_memory()
        print("Size is: " + size + "\nPeak is: " + peak)

    def stop_check_resources(self):
        tracemalloc.stop()

    # helper function
    def __write_exec_time_on_file(self, process_id, time, title, sim):
        with open("statistics/execution_times.csv", "a", newline="") as file:
            writer = csv.writer(file)
            if title:
                writer.writerow(["Process id", "Execution time", "Run"])
                return
            writer.writerow([process_id, time, sim])

    # helper function
    def __find_time_in_log_file(self, lines):
        start_time = 0
        end_time = 0
        for line in lines:
            if "EVALUATION CHECKPOINT" in line and start_time == 0:
                temp1 = re.findall("time.+[0-9]", line)
                temp2 = re.findall("[0-9]+", str(temp1))
                start_time = float(".".join(temp2))
            elif "MESSAGE DELIVERED" in line:
                temp1 = re.findall("time.+[0-9]", line)
                temp2 = re.findall("[0-9]+", str(temp1))
                end_time = float(".".join(temp2))
        return end_time - start_time

    # The following function gets execution time from log file
    # of each process and writes them in a file
    def create_execution_time_file(self, sim_number):
        for i in range(sim_number):
            folder = "debug/sim%i" % (i + 1)
            self.__write_exec_time_on_file(0, 0, True, 0)
            for filename in os.listdir(folder):
                if "debug" in filename:
                    # with open("folder/%s" % filename, "r", newline="\n") as file:
                    with open(folder + "/" + filename, "r", newline="\n") as file:
                        lines = file.readlines()

                        execution_time = self.__find_time_in_log_file(lines)
                        process_id = ".".join(re.findall("[0-9]+", filename))
                        self.__write_exec_time_on_file(
                            process_id, execution_time, False, i
                        )


if __name__ == "__main__":
    eval = Evaluation()
    # eval.create_execution_time_file()

    df = pd.read_csv("statistics/execution_times.csv")
    print(df)
    times_array = df["Execution time"].values

    avg_exec_time = np.average(times_array)
    std_exec_time = np.std(times_array)
    print(f"avg execution time: {avg_exec_time} ms")
    print(f"std execution time: {std_exec_time} ms")

    np.disp(times_array)
