import tracemalloc
import csv
import os
import re
import numpy as np
import pandas as pd
import time
import matplotlib.pyplot as plt
from matplotlib import style

PROCESS_STATS = 20


class Evaluation:
    def __init__(self, *args):
        if len(args) > 1:
            self.payload_sizes = args[0]
            self.num_rounds = args[1]
            self.num_simulations = args[2]
            self.algorithms = args[3]

    def tracing_start(self):
        tracemalloc.start()

    def tracing_stop(self):
        tracemalloc.stop()

    def tracing_mem(self):
        # peak memory is the maximum space the program used while executing
        size, peak = tracemalloc.get_traced_memory()
        self.tracing_stop()
        return peak / (1024 * 1024)  # returns peak expressed in MiB

    def set_checkpoint(self, *args):
        with open("execution_stats.csv", "a", newline="") as file:
            writer = csv.writer(file)

            # if memory stats is an argument then write it, otherwise write only time
            if len(args) > 0:
                writer.writerows(time.time() * 1000, args[0])
            else:
                writer.writerows(time.time() * 1000)

    def __write_stats_on_file(self, *args):
        # get type of algorithm
        algo = args[0]

        # build path to stat file
        path = os.path.join("stats-result", f"{algo}-Stats.csv")
        with open(path, "a", newline="") as file:
            writer = csv.writer(file)

            # other invocation writes data
            if len(args) > 1:
                time = args[1]
                peak_size = args[2]
                bw = args[3]
                processes = args[4]
                payload_size = args[5]
                round = args[6]
                sim = args[7]

                writer.writerow(
                    [time, peak_size, bw, processes, payload_size, round, sim]
                )

            # first invocation is used to write title
            else:
                writer.writerow(
                    [
                        "Avg time",
                        "Avg peak size",
                        "Avg bandwidth",
                        "Processes",
                        "Payload",
                        "Round",
                        "Simulation",
                    ]
                )

    def compute_avg(self, data):
        times = np.array([x[0] for x in data])
        peaks = np.array([x[1] for x in data])
        bytes_sent = np.array([x[2] for x in data])
        return np.average(times), np.average(peaks), np.average(bytes_sent)

    def __check_delivered(self, lines, name, path):
        # check if some process deliver, it may be redundant but it's statistic
        # computation and it's not required having high performance requirements in this phase
        found = False
        for line in lines:
            if "MESSAGE DELIVERED" in line:
                found = True
                break
        return found

    # helper function to find the execution function from debug file
    def __find_stats_in_log_file(self, lines, name, path):
        start_time = 0
        end_time = 0
        mem_peak_size = 0
        bytes_sent = []
        first = True  # Used only to avoid reading more than once MESSAGE DELIVERED

        if not self.__check_delivered(lines, name, path):
            print(f"not delivered in {name} {path}")
            return 0, 0, 0

        # execution time, peak size and bytes sent
        for line in lines:
            if "BYTES SENT" in line:
                # Define the regular expression pattern
                pattern = r"BYTES SENT: (\d+)"

                # Search for the pattern in the line
                match = re.search(pattern, line)

                # Check if a match was found
                if match:
                    bytes_sent.append(int(match.group(1)))

            if "EVALUATION CHECKPOINT" in line and start_time == 0:
                time_temp1 = re.findall("time.+[0-9]", line)
                time_temp2 = re.findall("[0-9]+", str(time_temp1))
                start_time = float(".".join(time_temp2))
            elif "MESSAGE DELIVERED" in line and first:
                first = False
                temp_string = re.findall("time.+[0-9]", line)[0]

                # Define a regular expression to parse the time and peak values
                pattern = r"time: ([\d\.]+), size: ([\d\.]+)"

                match = re.match(pattern, temp_string)
                if match:
                    end_time = float(match.group(1))
                    mem_peak_size = float(match.group(2))

        return [end_time - start_time, mem_peak_size, max(bytes_sent)]

    # The following function gets execution time from log file
    # of each process and writes them in a file
    def create_stats_file(self):
        for algo in self.algorithms:
            # Write columns on stats file
            self.__write_stats_on_file(algo)
            for size in self.payload_sizes:
                # size_path = f"simulations/payload_size{size}"
                size_path = os.path.join(algo, "simulations", f"payload_size{size}")

                for round in range(1, self.num_rounds + 1):
                    round_path = os.path.join(size_path, f"round{round}")

                    # data is a list which collects for each round the (time,peak,bytes)
                    # and it's used to compute the avarage of all those value
                    data = []
                    for simulation in range(1, self.num_simulations + 1):
                        execution_path = os.path.join(round_path, f"exec{simulation}")
                        data += self.find_execution_file(execution_path)

                    # compute the avg and write on file
                    time_avg, peak_avg, bytes_sent_avg = self.compute_avg(data)

                    # get avarage bandwidth in KB/s
                    bw_avg = bytes_sent_avg / (time_avg / 1024)

                    self.__write_stats_on_file(
                        algo,
                        time_avg,
                        peak_avg,
                        bw_avg,
                        2 * (round + 1),
                        size,
                        round,
                        simulation,
                    )

    # check whether stats files already exist
    def there_is_stats(self):
        count = 0
        for algo in self.algorithms:
            path = os.path.join("stats-result", f"{algo}-Stats.csv")
            if os.path.isfile(path):
                count += 1
        return count == len(self.algorithms)

    # helper function
    def find_execution_file(self, execution_path):
        data = []
        for filename in os.listdir(execution_path):
            if "debug" in filename:
                with open(f"{execution_path}/{filename}", "r", newline="\n") as file:
                    lines = file.readlines()

                    exec_time, peak_size, bytes_sent = self.__find_stats_in_log_file(
                        lines, filename, execution_path
                    )

                    # if delivered add stats
                    if exec_time != 0 and peak_size != 0 and bytes_sent != 0:
                        data.append((exec_time, peak_size, bytes_sent))
        return data

    def __plot_execution_time(self, df, ax, algo):
        for payload in self.payload_sizes:
            payload_df = df[df["Payload"] == payload]
            x = payload_df["Processes"]
            y = payload_df["Avg time"]

            ax.plot(x, y, label=f"Payload {payload} bytes")

        ax.set_title(f"{algo}")
        ax.set_xlabel("Number of Processes")
        ax.set_ylabel("Average Time (ms)")
        ax.legend().set_visible(False)  # Remove handlelength parameter

    def __plot_mem_usage(self, df, ax, algo):
        for payload in self.payload_sizes:
            payload_df = df[df["Payload"] == payload]
            x = payload_df["Processes"]
            y = payload_df["Avg peak size"]

            ax.plot(x, y, label=f"{payload} bytes")

        ax.set_title(f"{algo}")
        ax.set_xlabel("Number of Processes")
        ax.set_ylabel("Average Peak [MB]")

        ax.legend().set_visible(False)  # Hide individual legends

    def __plot_bw_usage(self, df, ax, algo):
        for payload in self.payload_sizes:
            payload_df = df[df["Payload"] == payload]
            x = payload_df["Processes"]
            y = payload_df["Avg bandwidth"]

            ax.plot(x, y, label=f"{payload} bytes")

        ax.set_title(f"{algo}")
        ax.set_xlabel("Number of Processes")
        ax.set_ylabel("BW [KB/s]")

        ax.legend().set_visible(False)  # Hide individual legends

    def plot_graphs(self):
        fig, axes = plt.subplots(
            len(self.algorithms), 3, figsize=(11, 9), clear=True, sharey="col"
        )

        # Adjust the layout and spacing between subplots
        plt.subplots_adjust(wspace=2, hspace=4)

        for i, algo in enumerate(self.algorithms):
            path = os.path.join("stats-result", f"{algo}-Stats.csv")
            stats_df = pd.read_csv(path)

            ax1 = axes[i, 0]
            ax2 = axes[i, 1]
            ax3 = axes[i, 2]

            ax1.set_xlim(4, 20)
            ax2.set_xlim(4, 20)
            ax3.set_xlim(4, 20)

            self.__plot_execution_time(stats_df, ax1, algo)
            self.__plot_mem_usage(stats_df, ax2, algo)
            self.__plot_bw_usage(stats_df, ax3, algo)

        labels = []
        for payload in self.payload_sizes:
            labels.append(str(payload) + " bytes")

        # Add a single common legend outside the subplots
        fig.legend(
            labels=labels,
            loc="upper center",
            bbox_to_anchor=(0.5, 1.02),
            ncol=4,
            borderpad=0.2,
            handleheight=4,
            columnspacing=1.5,
        )

        plt.tight_layout(h_pad=1.7, w_pad=1.5)
        plt.subplots_adjust(top=0.92)
        plt.show()

    def plot_bar_chart(self):
        time_data = {}
        memory_data = {}
        bw_data = {}
        for _, algo in enumerate(self.algorithms):
            path = os.path.join("stats-result", f"{algo}-Stats.csv")
            df = pd.read_csv(path)

            for p in self.payload_sizes:
                payload_df = df[df["Payload"] == p]
                filtered_by_payload = payload_df[
                    payload_df["Processes"] == PROCESS_STATS
                ]

                time_data[(algo, p)] = filtered_by_payload["Avg time"].values[0]
                memory_data[(algo, p)] = filtered_by_payload["Avg peak size"].values[0]
                bw_data[(algo, p)] = filtered_by_payload["Avg bandwidth"].values[0]

        # get time data
        time_final_data = {}
        for algo in self.algorithms:
            x = []  # payload
            y = []  # time

            for pair in time_data.keys():
                if algo in pair:
                    x.append(pair[1])
                    y.append(time_data[pair])

            time_final_data[algo] = (x, y)

        # get memory data
        mem_final_data = {}
        for algo in self.algorithms:
            x = []  # payload
            y = []  # time
            for pair in memory_data.keys():
                if algo in pair:
                    x.append(pair[1])
                    y.append(memory_data[pair])

            mem_final_data[algo] = (x, y)

        # get bandwidth data
        bw_final_data = {}
        for algo in self.algorithms:
            x = []  # payload
            y = []  # bandwidth
            for pair in bw_data.keys():
                if algo in pair:
                    x.append(pair[1])
                    y.append(bw_data[pair])

            bw_final_data[algo] = (x, y)

        fig, axes = plt.subplots(1, 3, figsize=(10, 10), clear=True)

        style.use("ggplot")

        ax1 = axes[0]
        ax2 = axes[1]
        ax3 = axes[2]

        xpos = np.arange(len(self.payload_sizes))

        ax1.set_xticks(xpos + 0.3, self.payload_sizes)
        ax2.set_xticks(xpos + 0.3, self.payload_sizes)
        ax3.set_xticks(xpos + 0.3, self.payload_sizes)

        ax1.set_xlabel("Payload [Bytes]")
        ax2.set_xlabel("Payload [Bytes]")
        ax3.set_xlabel("Payload [Bytes]")

        ax1.set_ylabel("time [ms]")
        ax2.set_ylabel("peak [MB]")
        ax3.set_ylabel("bandwidth [KB/s]")

        for i, algo in enumerate(self.algorithms):
            x = time_final_data[algo][0]
            y_time = time_final_data[algo][1]
            y_mem = mem_final_data[algo][1]
            y_bw = bw_final_data[algo][1]

            xpos = np.arange(len(x))

            ax1.bar(
                xpos + i * 0.2,
                y_time,
                label=algo,
                width=0.2,
            )
            ax2.bar(
                xpos + i * 0.2,
                y_mem,
                label=algo,
                width=0.2,
            )
            ax3.bar(
                xpos + i * 0.2,
                y_bw,
                label=algo,
                width=0.2,
            )

            ax1.legend(loc="upper right")
            ax2.legend(loc="upper right")
            ax3.legend(loc="upper right")

        plt.tight_layout(w_pad=2)
        plt.legend()
        plt.show()

    def plot_all(self):
        self.plot_graphs()
        self.plot_bar_chart()
