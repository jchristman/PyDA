from threading import Thread, Condition
from Queue import Queue

class ThreadPoolExecutor:
    '''
    My own personal implementation of concurrent.futures.ThreadPoolExecutor
    as it does not exist in the default packages of Python 2.7. I didn't want
    people to have to install a dependency, so I wrote my own class. It mimics
    the actual concurrent.futures.ThreadPoolExecutor
    '''
    def __init__(self, max_workers=8):
        self.function_queue = Queue()
        self.activate_worker = Condition()
        self.shut_down = False
        self.workers = [Thread(target=self.worker) for i in xrange(max_workers)]
        for thread in self.workers: thread.start()

    def worker(self):
        self.activate_worker.acquire()
        try:
            while not self.shut_down:
                while not self.function_queue.empty():
                    try:    self.do_work(self.function_queue.get(False))
                    except: pass
                    if self.shut_down: raise ShutdownException
                self.activate_worker.wait()
        except Exception:
            pass
        self.activate_worker.release()

    def do_work(self, args):
        fn, args, kwargs = args
        fn(*args, **kwargs)

    def submit(self, fn, *args, **kwargs):
        self.activate_worker.acquire()
        self.function_queue.put((fn, args, kwargs))
        self.activate_worker.notify()
        self.activate_worker.release()

    def map(self, func, iterables, timeout=None):
        for data in iterables:
            self.function_queue.put((func, data, {}))
        self.activate_worker.acquire()
        self.activate_worker.notifyAll()
        self.activate_worker.release()

    def shutdown(self, wait=True):
        self.shut_down = True
        self.activate_worker.acquire()
        self.activate_worker.notifyAll()
        self.activate_worker.release()
        if wait:
            for worker in self.workers:
                worker.join()

class ShutdownException(Exception):
    pass
