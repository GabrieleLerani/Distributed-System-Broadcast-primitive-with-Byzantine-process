import time
import tracemalloc

class Evaluation:
    def __init__(self):
        self.start = 0
        self.end = 0
        self.snap = []

    def check_time(self):
        if self.start != 0:
            self.end = time.time()
            temp = self.end - self.start
            self.start = 0
            self.end = 0
            print(temp)
        self.start = time.time()

    def start_check_resources(self):
        tracemalloc.start()

    def take_snapshot(self, flag):
        self.snap.append([tracemalloc.take_snapshot(), flag])

    def snap_diff(self):
        compare = self.snap[len(self.snap) - 1].compare_to(self.snap[len(self.snap) - 2], 'lineno', False)
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
