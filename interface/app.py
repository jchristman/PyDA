'''
Author: Joshua Christman

This file is the root tkinter application base for PyDA. It subclasses the main
tk root so that I can add a callback queue to the root in order to put large
amounts of GUI operations into a queue that will execute in such a way as to
prevent the GUI from blocking.
'''

from Tkinter import Tk
from maininterface import PyDAInterface
from Queue import Queue

def build_and_run(settings_manager, disassembler, executor, server):
    '''
    Arguments:
    disassembler - the PyDA disassembler class that contains methods for GUI operations
    server - the PyDA server that will be used for multiplayer work
    '''

    root = RootApplication(settings_manager, disassembler, executor, server)
    try:    app = PyDAInterface(root)
    except: root.shutdown(); exit()
    try:    root.mainloop()
    except: root.shutdown()

class RootApplication(Tk):
    '''
    Arguments:
    disassembler - the PyDA disassembler class that contains methods for GUI operations
    server - the PyDA server that will be used for multiplayer work

    Description:
    The root Tk object that subclass the regular Tkinter one and adds a callback queue
    that executes a predetermined amount every so often. It allows the callback GUI effects
    to take place and keeps the GUI from blocking with a large number of operations.
    '''
    def __init__(self, settings_manager, disassembler, executor, server):
        Tk.__init__(self)
        Tk.CallWrapper = RootApplication.AppCallWrapper
        self.settings_manager = settings_manager
        self.disassembler = disassembler
        self.executor = executor
        self.server = server
        self.queue_process_amount = settings_manager.getint('application', 'queue-process-amount')
        self.queue_process_delay = settings_manager.getint('application', 'queue-process-delay')
        self.queues = []

    def createCallbackQueue(self):
        self.queues.append(Queue())
        self.after(self.queue_process_delay, self.pollCallbackQueue, self.queues[-1])
        return self.queues[-1]

    def addCallback(self, queue, callback, args=None, kwargs=None):
        '''
        Arguments:
        callback - a function pointer that should be called when the item is called up in the queue
        args - a tuple of arguments
        kwargs - a tuple of keyword arguments !!! NOT YET VERIFIED TO WORK !!!
        '''
        queue.put((callback, args, kwargs))

    def pollCallbackQueue(self, queue):
        '''
        Change settings inside of settings.py to change the frequency of calls to this function as well
        as the amount of queue items to process per call.
        '''
        for i in xrange(self.queue_process_amount):
            if queue.empty():
                break

            callback,args,kwargs = queue.get()
            if args:
                if kwargs:
                    callback(*args, **kwargs)
                else:
                    callback(*args)
            else:
                if kwargs:
                    callback(**kwargs)
                else:
                    callback()
        
        self.after(self.queue_process_delay, self.pollCallbackQueue, queue)

    def destroy(self):
        self.shutdown()

    def shutdown(self):
        self.executor.shutdown()
        self.quit()

    class AppCallWrapper:
        def __init__(self, func, subst, widget):
            self.func = func
            self.subst = subst
            self.widget = widget

        def __call__(self, *args):
            try: 
                if self.subst: 
                    args = apply(self.subst, args) 
                    return apply(self.func, args) 
            except KeyboardInterrupt:
                raise KeyboardInterrupt
            except SystemExit, msg:
                raise SystemExit, msg
            except Exception as e:
                raise Exception

if __name__ == '__main__':
    build_and_run()
