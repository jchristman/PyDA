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
import sys

def build_and_run(settings_manager, disassembler, executor, server, save_manager):
    '''
    Arguments:
    disassembler - the PyDA disassembler class that contains methods for GUI operations
    server - the PyDA server that will be used for multiplayer work
    '''
    root = RootApplication(settings_manager, disassembler, executor, server, save_manager)
    print 'Building app'
    try:    app = PyDAInterface(root)
    except Exception as e:
        print 'Exception in building interface!\n',e.message
        root.shutdown()
        sys.exit()
    except:
        root.shutdown()
        sys.exit()
    print 'Running mainloop'
    try:    root.mainloop()
    except Exception as e:
        print 'Exception in mainloop!\n',e.message
        root.shutdown()
    except:
        root.shutdown()
    print 'Exiting'

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
    def __init__(self, settings_manager, disassembler, executor, server, save_manager):
        Tk.__init__(self)
        Tk.CallWrapper = AppCallWrapper
        self.settings_manager = settings_manager
        self.disassembler = disassembler
        self.executor = executor
        self.server = server
        self.save_manager = save_manager
        
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

    def save(self, file_path, disassembly_object):
        save_data = (self.settings_manager, self.disassembler, disassembly_object) # We are just saving a tuple of objects right now...
        self.save_manager.save(file_path, save_data)

    def load(self, file_path):
        object_tuple = self.save_manager.load(file_path)
        if object_tuple is None:
            return None
        self.settings_manager, self.disassembler, disassembly_object = object_tuple # Unpack the objects
        return disassembly_object

    def destroy(self):
        self.shutdown()

    def shutdown(self):
        print 'Shutting down'
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
            raise
        except SystemExit, msg:
            raise SystemExit, msg

if __name__ == '__main__':
    build_and_run()
