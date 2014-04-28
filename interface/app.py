# Author: Joshua Christman
#
# This file is the root tkinter application base for PyDA. It subclasses the main
# tk root so that I can add a callback queue to the root in order to put large
# amounts of GUI operations into a queue that will execute in such a way as to
# prevent the GUI from blocking.

from Tkinter import Tk
from maininterface import PyDAInterface
from Queue import Queue

def build_and_run(disassembler, server):
    '''
    Arguments:
    disassembler - the PyDA disassembler class that contains methods for GUI operations
    server - the PyDA server that will be used for multiplayer work
    '''

    root = RootApplication()
    app = PyDAInterface(root, disassembler, server)
    root.mainloop()

class RootApplication(Tk):
    '''
    The root Tk object that subclass the regular Tkinter one and adds a callback queue
    that executes a predetermined amount every so often. It allows the callback GUI effects
    to take place and keeps the GUI from blocking with a large number of operations.
    '''
    def __init__(self):
        Tk.__init__(self)
        self.callback_queue = Queue()
        self.pollCallbackQueue()

    # TODO: Rework progress monitor code
    '''
    def startProgressMonitor(self, callback):
        self.progress_monitor = True
        self.progress_point_callback = callback

    def stopProgressMonitor(self):
        self.progress_monitor = False
    
    def addProgressPoint(self):
        self.addCallback('PROGRESS POINT')

    def addBreak(self):
        self.addCallback('BREAK')'''

    def addCallback(self, callback, args=None, kwargs=None):
        '''
        Arguments:
        callback - a function pointer that should be called when the item is called up in the queue
        args - a tuple of arguments
        kwargs - a tuple of keyword arguments !!! NOT YET VERIFIED TO WORK !!!
        '''
        self.callback_queue.put((callback, args, kwargs))

    def pollCallbackQueue(self):
        pollProcessSize = 500
        progress_points = 0

        for i in xrange(pollProcessSize):
            if self.callback_queue.empty() or self.wait_for_queue:
                break

            callback,args,kwargs = self.callback_queue.get()
            if callback == 'PROGRESS POINT':
                progress_points += 1
            elif callback == 'BREAK':
                break
            elif args:
                if kwargs:
                    callback(*args, **kwargs)
                else:
                    callback(*args)
            else:
                if kwargs:
                    callback(**kwargs)
                else:
                    callback()

        self.total_points += progress_points
        self.wait_for_queue = False

        if self.progress_monitor:
            self.progress_point_callback(progress_points)
        
        self.after(10, self.pollCallbackQueue)

if __name__ == '__main__':
    build_and_run()
