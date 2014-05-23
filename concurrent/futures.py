from threading import Thread, Condition
from multiprocessing import Process, Pipe
from Queue import Queue
from cProfile import Profile
from pstats import Stats
from cStringIO import StringIO
import pickle, cPickle

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
        fn, args, kwargs = args
        if profile: profile.enable()
        fn(*args, **kwargs)
        if profile:
            profile.disable()
            if self.stats == None: self.stats = Stats(profile)
            else: self.stats.add(profile)

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

    def getProfileStats(self):
        return self.stats

def _process(cmd_pipe, data_pipe, process_object):
    cmd, args = cPickle.loads(cmd_pipe.recv())
    while not 'halt' in cmd:
        string_io = StringIO()
        result = process_object.execute(cmd, args)
        cPickle.dump(result, string_io)
        data_pipe.send(string_io.getvalue())
        string_io.close()
        cmd, args = cPickle.loads(cmd_pipe.recv())
    return

class ProcessProxy:
    def __init__(self, process_object):
        if not isinstance(process_object, AbstractProcessObject):
            raise NotAbstractProcessObjectException
        self.parent_cmd_pipe, self.child_cmd_pipe = Pipe()
        self.parent_data_pipe, self.child_data_pipe = Pipe()
        self.process = Process(target=_process, args=(self.child_cmd_pipe, self.child_data_pipe, process_object))
        self.process.start()

    def submit(self, cmd_str, args_tuple, callback=None):
        string_io = StringIO()
        pickle.dump((cmd_str, args_tuple), string_io)
        self.parent_cmd_pipe.send(string_io.getvalue())
        string_io.close()
        result = pickle.loads(self.parent_data_pipe.recv())
        if callback:
            callback(result)
        return result

    def shutdown(self, hard=False):
        if hard:    self.process.terminate()
        else:       self.parent_cmd_pipe.send('halt')
        self.process.join()

class AbstractProcessObject:
    def execute(self, cmd_str):
        raise NotImplementedError

class DisassemblerInterface:
    def __init__(self, process_object):
        self.process_proxy = ProcessProxy(process_object)

    def disassemble(self, file_name, callback=None):
        self.process_proxy.submit('DISASSEMBLE', file_name)
        if callback:
            callback()

    def get(self, arg1, arg2, arg3, key=None):
        return self.process_proxy.submit('GET', (arg1, arg2, arg3, key))

    def getitem(self, index, key=None):
        return self.process_proxy.submit('GETITEM', (index, key))

    def set(self, index, item, key=None):
        return self.process_proxy.submit('SET', (index, item, key))

    def append(self, item, key=None):
        return self.process_proxy.submit('APPEND', (item, key))

    def search(self, string, key=None):
        return self.process_proxy.submit('SEARCH', (string, key))

    def length(self, key=None):
        return self.process_proxy.submit('LENGTH', (key,))

    def shutdown(self, hard=False):
        self.process_proxy.shutdown()

class ShutdownException(Exception):
    pass

class NotAbstractProcessObjectException(Exception):
    pass

class UnknownProcessCommandException(Exception):
    pass
