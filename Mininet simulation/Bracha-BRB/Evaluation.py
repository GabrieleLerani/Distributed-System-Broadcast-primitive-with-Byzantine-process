import tracemalloc
import csv
import os
import re
import threading
import psutil
import logging
import numpy as np
import pandas as pd
import utils
import matplotlib.pyplot as plt

CPU_SAMPLING_FREQUENCY = 0.005


class Evaluation:
    def __init__(self, *args):
        if len(args) > 1:
            self.payload_sizes = args[0]
            self.num_rounds = args[1]
            self.num_simulations = args[2]
        self.cpu_values = np.array([])  # TODO remove

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

    def __write_stats_on_file(self, *args):
        # path = args[0]
        with open("statistics/stats.csv", "a", newline="") as file:
            writer = csv.writer(file)

            if len(args) > 0:
                time = args[0]
                peak_size = args[1]
                processes = args[2]
                payload_size = args[3]
                round = args[4]
                sim = args[5]

                writer.writerow([time, peak_size, processes, payload_size, round, sim])

            else:
                writer.writerow(
                    [
                        "Avg time",
                        "Avg peak size",
                        "Processes",
                        "Payload",
                        "Round",
                        "Simulation",
                    ]
                )

    def compute_avg(self, pair):
        times = np.array([x[0] for x in pair])
        peaks = np.array([x[1] for x in pair])
        return np.average(times), np.average(peaks)

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
    def create_stats_file(self):
        # Write columns on stats file
        self.__write_stats_on_file()
        for size in self.payload_sizes:
            size_path = f"simulations/payload_size{size}"

            for round in range(1, self.num_rounds + 1):
                round_path = f"{size_path}/round{round}"

                # pair is a list which collects for each round the pair (time,peak)
                # and it's used to compute the avarage of all those value
                pair = []
                for simulation in range(1, self.num_simulations + 1):
                    execution_path = f"{round_path}/exec{simulation}"
                    pair += self.find_execution_file(execution_path)

                # I compute the avg and i write
                time_avg, peak_avg = self.compute_avg(pair)
                self.__write_stats_on_file(
                    time_avg,
                    peak_avg,
                    2 * (round + 1),
                    size,
                    round,
                    simulation,
                )

    # helper function
    def find_execution_file(self, execution_path):
        pair = []
        for filename in os.listdir(execution_path):
            if "debug" in filename:
                with open(f"{execution_path}/{filename}", "r", newline="\n") as file:
                    lines = file.readlines()

                    exec_time, peak_size = self.__find_stats_in_log_file(lines)
                    pair.append((exec_time, peak_size))
        return pair

    def __plot_execution_time(self, df, ax1):
        payloads = np.unique(df["Payload"].values)
        ticks = np.unique(df["Processes"].values)
        xpoint = np.array([])
        ypoint = np.array([])

        for payload in payloads:
            points = df[df["Payload"] == payload]
            xpoint = points["Processes"]
            ypoint = points["Avg time"]

            ax1.plot(xpoint, ypoint, label=f"payload {payload} bytes")

        ax1.set_title("Execution time")
        ax1.set_xticks(ticks)
        ax1.set_xlabel("number of processes")
        ax1.set_ylabel("avg time (ms)")
        ax1.legend()

    def __plot_mem_usage(self, df, ax2):
        payloads = np.unique(df["Payload"].values)
        ticks = np.unique(df["Processes"].values)
        xpoint = np.array([])
        ypoint = np.array([])

        for payload in payloads:
            points = df[df["Payload"] == payload]
            xpoint = points["Processes"]
            ypoint = points["Avg peak size"]

            ax2.plot(xpoint, ypoint, label=f"payload {payload} bytes")

        ax2.set_title("Memory")
        ax2.set_xticks(ticks)
        ax2.set_xlabel("number of processes")
        ax2.set_ylabel("avg peak (MB)")
        ax2.legend()

    def plot_graphs(self):
        stats_df = pd.read_csv("statistics/stats.csv")
        print(stats_df)

        fig, (ax1, ax2) = plt.subplots(1, 2)

        self.__plot_execution_time(stats_df, ax1)
        self.__plot_mem_usage(stats_df, ax2)

        plt.show()


# if __name__ == "__main__":
#     stats_df = pd.read_csv("statistics/stats.csv")

#     eval = Evaluation()
#     fig, (ax1, ax2) = plt.subplots(1, 2)

#     eval.plot_execution_time(stats_df, ax1)
#     eval.plot_mem_usage(stats_df, ax2)

#     plt.show()

#     pass
