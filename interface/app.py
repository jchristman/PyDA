'''
Author: Joshua Christman

This file is the root tkinter application base for PyDA. It subclasses the main
tk root so that I can add a callback queue to the root in order to put large
amounts of GUI operations into a queue that will execute in such a way as to
prevent the GUI from blocking.
'''

from Tkinter import Tk
from maininterface import PyDAInterface
from settings import QUEUE_PROCESS_AMT,QUEUE_PROCESS_DELAY
from Queue import Queue

def build_and_run(disassembler, executor, server):
    '''
    Arguments:
    disassembler - the PyDA disassembler class that contains methods for GUI operations
    server - the PyDA server that will be used for multiplayer work
    '''

    root = RootApplication(disassembler, executor, server)
    app = PyDAInterface(root)
    root.mainloop()

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
    def __init__(self, disassembler, server):
        Tk.__init__(self)
        
        self.disassembler = disassembler
        self.server = server
        self.queues = []

    def createCallbackQueue(self):
        self.queues.append(Queue())
        self.after(QUEUE_PROCESS_DELAY, self.pollCallbackQueue, self.queues[-1])
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
        for i in xrange(QUEUE_PROCESS_AMT):
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
        
        self.after(QUEUE_PROCESS_DELAY, self.pollCallbackQueue, queue)

if __name__ == '__main__':
    build_and_run()
