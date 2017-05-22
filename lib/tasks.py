try:
    from Queue import Queue
except ImportError:
    from queue import Queue
from threading import Lock, Thread
import csv
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
result_path = os.path.join(BASE_DIR, 'result')
from base import Base
#Type,Name,Address,Target,Port,String


class Worker(Thread):
    """Thread executing tasks from a given tasks queue"""

    lck = Lock()

    def __init__(self, tasks,filename=None):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.result_dict=os.path.join(result_path,filename)
        self.start()
        # Global variable that will hold the results

    def run(self):

        found_record = []
        while True:
            tmp=Base()
            (func, args, kargs) = self.tasks.get()
            try:
                found_record = func(*args, **kargs)
                if found_record:
                    Worker.lck.acquire()
                    # brtdata.append(found_record)
                    self.write_csv(found_record)
                    for r in found_record:
                        data=[]
                        data.append(r['Type'])
                        data.append(r['Name'])
                        data.append(r['Address'])
                        data.append(r['Target'])
                        data.append(r['Port'])
                        data.append(r['String'])
                        msg=' '.join(data)
                        tmp.print_good(msg)
                        # # if type(r).__name__ == "dict":
                        # #     for k, v in r.iteritems():
                        #         tmp.print_good("\t{0}:{1}".format(k, v))
                        #     print_status()
                        # else:
                        #     print_status("\t {0}".format(" ".join(r)))
                    Worker.lck.release()

            except Exception as e:
                tmp.print_debug(e)
            self.tasks.task_done()
    def write_csv(self,found_record):
        if os.path.exists(self.result_dict):
            c=open(self.result_dict,'a')
        else:
            c=open(self.result_dict,'w')
        writer=csv.writer(c)
        tmp_len = len(found_record)
        for r in found_record:
            data = []
            data.append(r['Type'])
            data.append(r['Name'])
            data.append(r['Address'])
            data.append(r['Target'])
            data.append(r['Port'])
            data.append(r['String'])
            writer.writerow(data)



class ThreadPool:
    """Pool of threads consuming tasks from a queue"""

    def __init__(self, num_threads,filename=None):
        if filename is None:
            tmp=Base()
            filename=tmp.get_random_str(10)+'.csv'
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks,filename)

    def add_task(self,
                 func,
                 *args,
                 **kargs):
        """Add a task to the queue"""

        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        """Wait for completion of all the tasks in the queue"""

        self.tasks.join()

    def count(self):
        """Return number of tasks in the queue"""

        return self.tasks.qsize()