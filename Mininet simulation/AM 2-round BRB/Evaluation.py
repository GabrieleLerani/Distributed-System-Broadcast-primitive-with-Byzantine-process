import tracemalloc
import csv
import os
import re
import threading
import psutil
import logging
import numpy as np
import pandas as pd

CPU_SAMPLING_FREQUENCY = 0.005


class Evaluation:
    def __init__(self, *args):
        if len(args) > 1:
            self.proc_number = args[0]
            self.sim_number = args[1]
        self.cpu_values = np.array([])

    def tracing_start(self):
        tracemalloc.start()

    def tracing_stop(self):
        tracemalloc.stop()

    def tracing_mem(self):
        # peak memory is the maximum space the program used while executing
        size, peak = tracemalloc.get_traced_memory()
        self.tracing_stop()
        return peak / (1024 * 1024)  # returns peak expressed in KiB

    def monitor_cpu(self):
        global running
        running = True
        currentProcess = psutil.Process()

        # start loop
        while running:
            value = currentProcess.cpu_percent(interval=CPU_SAMPLING_FREQUENCY)
            print("CPU value:", value)
            self.cpu_values = np.append(self.cpu_values, value)

    def start_cpu_monitoring(self):
        global t

        # create thread and start it
        t = threading.Thread(target=self.monitor_cpu)
        t.start()

    def stop_cpu_monitoring(self):
        global running
        global t

        # use `running` to stop loop in thread so thread will end
        running = False

        # wait for thread's end
        t.join()

        # write cpu usage to file
        self.__write_cpu_file()

    def __write_cpu_file(self):
        self.cpu_values.tofile("statistics/cpu_usage.csv", sep=",")

    # helper function to write stats time on file
    def __write_stats_on_file(self, process_id, time, peak_size, sim, title):
        with open("statistics/stats.csv", "a", newline="") as file:
            writer = csv.writer(file)
            if title:
                writer.writerow(
                    [
                        "Process id",
                        "Execution time",
                        "Peak size",
                        "Run",
                    ]
                )
                return
            writer.writerow([process_id, time, peak_size, sim])

    # helper function to find the execution function from debug file
    def __find_stats_in_log_file(self, lines):
        start_time = 0
        end_time = 0
        mem_peak_size = 0
        # check if some process deliver, it may be redundant but it's statistic
        # computation and it's not required having high performance requirements in this phase
        found = False
        for line in lines:
            if "MESSAGE DELIVERED" in line:
                found = True
                break
        if not found:
            logging.info("MESSAGE NOT DELIVERED FOR SOME PROCESS")
            exit(-1)

        for line in lines:
            if "EVALUATION CHECKPOINT" in line and start_time == 0:
                time_temp1 = re.findall("time.+[0-9]", line)
                time_temp2 = re.findall("[0-9]+", str(time_temp1))
                start_time = float(".".join(time_temp2))
            elif "MESSAGE DELIVERED" in line:
                temp_string = re.findall("time.+[0-9]", line)[0]

                # Define a regular expression to parse the time and peak values
                pattern = r"time: ([\d\.]+), size: ([\d\.]+)"

                match = re.match(pattern, temp_string)
                if match:
                    end_time = float(match.group(1))
                    mem_peak_size = float(match.group(2))
                else:
                    print("No time and peak match in file")

        return end_time - start_time, mem_peak_size

    # The following function gets execution time from log file
    # of each process and writes them in a file
    def create_stats_file(self, sim_number):
        # following code used to write stats column title
        self.__write_stats_on_file(0, 0, 0, 0, True)
        for i in range(sim_number):
            folder = "simulations/sim%i" % (i + 1)
            for filename in os.listdir(folder):
                if "debug" in filename:
                    # with open("folder/%s" % filename, "r", newline="\n") as file:
                    with open(folder + "/" + filename, "r", newline="\n") as file:
                        lines = file.readlines()
                        execution_time, peak_size = self.__find_stats_in_log_file(lines)
                        process_id = ".".join(re.findall("[0-9]+", filename))
                        self.__write_stats_on_file(
                            process_id, execution_time, peak_size, i + 1, False
                        )


if __name__ == "__main__":
    # eval = Evaluation(8, 3)
    # eval.create_stats_file(eval.sim_number)

    df = pd.read_csv("statistics/stats.csv")
    print(df)
    times_array = df["Execution time"].values
    peaks_array = df["Peak size"].values

    avg_exec_time = np.average(times_array)
    std_exec_time = np.std(times_array)
    avg_peak = np.average(peaks_array)
    std_peak = np.std(peaks_array)

    print(f"avg execution time: {avg_exec_time} ms")
    print(f"std execution time: {std_exec_time} ms")
    print(f"std peak size: {avg_peak} KiB")
    print(f"std peak size: {std_peak} KiB")