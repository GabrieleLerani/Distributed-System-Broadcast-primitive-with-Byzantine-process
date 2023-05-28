import tracemalloc


class Evaluation:
    def __init__(self, *args):
        if len(args) > 1:
            self.payload_sizes = args[0]
            self.num_rounds = args[1]
            self.num_simulations = args[2]

    def tracing_start(self):
        tracemalloc.start()

    def tracing_stop(self):
        tracemalloc.stop()

    def tracing_mem(self):
        # peak memory is the maximum space the program used while executing
        size, peak = tracemalloc.get_traced_memory()
        self.tracing_stop()
        return peak / (1024 * 1024)  # returns peak expressed in KiB
