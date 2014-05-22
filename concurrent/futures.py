from threading import Thread, Condition
from multiprocessing import Process, Pipe
import cPickle
import pickle
from cStringIO import StringIO
from Queue import Queue
from cProfile import Profile
from pstats import Stats

### These next lines are used to enable ccPickle to effectively cPickle objects
### for interprocess communication
def _cPickle_method(method):
    func_name = method.im_func.__name__
    obj = method.im_self
    cls = method.im_class
    return _uncPickle_method, (func_name, obj, cls)

def _uncPickle_method(func_name, obj, cls):
    try:
        for cls in cls.mro():
            try:
                func = cls.__dict__[func_name]
            except KeyError:
                pass
            else:
                break
    except AttributeError:
        func = cls.__dict__[func_name]
    return func.__get__(obj, cls)

import copy_reg
import types
copy_reg.pickle(types.MethodType, _cPickle_method, _uncPickle_method)

def _do_work(child, fn, args, kwargs):
    string_io = StringIO() # This is a fast, file like object in RAM we can dump to with cPickle
    print 'Starting the function'
    data = fn(*args, **kwargs)
    print 'Pickling the object'
    cPickle.dump(data, string_io)
    print 'Sending data to parent'
    child.send(string_io.getvalue())
    print 'Done!'
    child.close()
    return

class ThreadPoolExecutor:
    '''
    My own personal implementation of concurrent.futures.ThreadPoolExecutor
    as it does not exist in the default packages of Python 2.7. I didn't want
    people to have to install a dependency, so I wrote my own class. It mimics
    the actual concurrent.futures.ThreadPoolExecutor
    '''
    def __init__(self, max_workers=8, profiler_on=0):
        self.profiler_on = profiler_on
        if self.profiler_on:
            self.stats = None

        self.function_queue = Queue()
        self.activate_worker = Condition()
        self.shut_down = False
        self.workers = [Thread(target=self.worker) for i in xrange(max_workers)]
        for thread in self.workers: thread.start()

    def worker(self):
        profile = None
        if self.profiler_on:
            profile = Profile()
        self.activate_worker.acquire()
        try:
            while not self.shut_down:
                while not self.function_queue.empty():
                    try:    self.do_work(self.function_queue.get(False), profile)
                    except: raise
                    if self.shut_down: raise ShutdownException
                self.activate_worker.wait()
        except ShutdownException: pass
        except: raise
        self.activate_worker.release()

    def do_work(self, args, profile):
        fn, args, kwargs, in_process, callback = args
        if profile: profile.enable()
        if in_process:
            parent, child = Pipe()
            p = Process(target=_do_work, args=(child, fn, args, kwargs))
            print 'Starting process'
            p.start()
            print 'Receiving data'
            data = parent.recv()
            print 'Waiting on end of process'
            p.join()
            parent.close()
            data = cPickle.loads(data) # It's slower but it doesn't lock the GIL....
            print 'Finished and got', data
            if profile:
                profile.disable()
                if self.stats == None: self.stats = Stats(profile)
                else: self.stats.add(profile)
            callback(data)
        else:
            fn(*args, **kwargs)
            if profile:
                profile.disable()
                if self.stats == None: self.stats = Stats(profile)
                else: self.stats.add(profile)

    def submit(self, fn, *args, **kwargs):
        self.activate_worker.acquire()
        self.function_queue.put((fn, args, kwargs, False, None))
        self.activate_worker.notify()
        self.activate_worker.release()

    def submitProcess(self, fn, callback, *args, **kwargs):
        self.activate_worker.acquire()
        self.function_queue.put((fn, args, kwargs,  True, callback))
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

    def getProfileStats(self):
        return self.stats

class ShutdownException(Exception):
    pass
