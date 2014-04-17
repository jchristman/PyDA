'''
nexpect.py
Authors: Josh Christman and Nathan Hart
Version: 1.0.6
Date: 8 December 2013

Changelog (v1.0.6):
    - Created new method: n.expectnl() which will expect a newline and not include the newline in the result it returns. I'm adding this because of
        how often I do n.expect('\\n', incl=False)

Changelog (v1.0.5):
    - Added a global recvsize variable which will a permanent change to the number of bytes received per test of the regexes in the expect modules.
    - Rearranged some code to more efficiently use global variables recvsize and timeout

Changelog (v1.0.4):
    - Fixed a bug in the expect method that was keeping the incl flag from working
    - Made the sendline and send methods always cast the data to a str before doing anything
        - This makes it possible to do sendline(1) and it send the number 1 and concatenate without having to cast to a string on the user side
'''

import threading,sys,socket,re,time

def spawn(sock, timeout=30, withSSL=False):
    return nexpect(sock, timeout=timeout, withSSL=withSSL)

'''
The class nexpect is a socket expect module written using basic python modules. It should work on any
system with Python 2.7
'''
class nexpect():
    '''
    The constructor has one mandatory parameter:
        sock - This can be either a tuple with an address and port to connect to, or a socket object.
        Ex: s = nexpect(('www.example.com',1234))
        
            s = nexpect(('123.123.123.123',1234))

            sock = socket.socket()
            sock.connect(('www.example.com',1234))
            s = nexpect(sock)

    Optional parameters are:
        timeout - Sets the class timeout variable used as the timeout for the expect method
    '''
    def __init__(self, sock, timeout=30, recvsize=1, withSSL=False):
        self.timeout = timeout
        self.recvsize = recvsize
        self.before = ''
        self.matched = ''
        if type(sock) == type(()):
            self.socket = socket.socket()
            if withSSL:
                import ssl
                self.socket = ssl.wrap_socket(self.socket)
            self.socket.connect(sock)
        elif type(sock) == type(socket.socket()):
            self.socket = sock
        else:
            raise TypeError

    '''
    This method does nothing but call the send method of the socket and pass the data to the socket
    '''
    def send(self, data=''):
        self.socket.sendall(str(data))

    '''
    This method appends a delimeter to the data and then sends it to the socket

    Optional parameters are:
        delimeter - Defaults to a '\n' but can be set to anything
    '''
    def sendline(self, data='', delimeter='\n'):
        self.socket.sendall(str(data) + delimeter)
    
    '''
    A convience method to access the underlying socket's recv mechanism.
    '''
    def recv(self, num_bytes):
        return self.socket.recv(num_bytes)

    '''
    This function takes a single regex in string form or a list/tuple of string regexes and receives data
    on the socket until it matches the regex. If a single regex is passed in, only the data received is
    returned from the function. If a list/tuple of regexes is passed in, the function returns a tuple of
    the data and the index of the regex it matched. It will print the data that didn't match any regexes
    if it times out so you can see why it didn't actually match any regexes.

    Optional parameters are:
        recvsize - the size of the data to receive each time through the loop. It defaults to 1 but can
        be slow this way. Increase this if you know that the data being sent to you will be fairly regular.

        timeout - a local timeout override to the class variable timeout. This can be used for a time when
        you want a different timeout than the normal.

        incl - a variable that you can set to false if you don't want the regex you're matching to be returned
        as part of the data. Example: n.expect('>',incl=False) on "prompt >" would return "prompt "
    '''
    def expect(self, regex, recvsize=-1, timeout=-1, incl=True):
        if recvsize == -1:
            recvsize = self.recvsize
        if timeout == -1:
            timeout = self.timeout
        isList = False
        if type(regex) == type(()) or type(regex) == type([]):
            isList = True

        data = ''
        t0 = time.time()
        while True:
            
            t1 = time.time()
            elapsedTime = t1-t0                 # Get the elapsed time since before the receive loop started

            if elapsedTime > timeout:           # Test the timeout
                raise TimeoutException('Data received before timeout: "' + data + '"')
            else:    
                # If it hasn't timed out, set the socket's timeout so that it won't block forever
                self.socket.settimeout(timeout - elapsedTime)

            # Now receive the data
            try:
                data += self.socket.recv(recvsize)
            except:
                # I know - catching an exception to raise another one means I'm evil. Sorry!
                raise TimeoutException('Data received before timeout: "' + data + '"')
           
            # Data was received - time to check the data to see if it matches the regexes
            if isList:                                  # Check if a list or tuple of regexes was passed in
                for counter,reg in enumerate(regex):    # Enumerate the regexes for testing
                    match = re.search(reg, data)
                    if match:
                        if not incl:
                            data = data.replace(match.group(0), "")    # Will replace the match with a blank string
                        self.before = data
                        self.matched = reg
                        return data, counter            # Return the data and the index of the regex found
            else:
                match = re.search(regex, data)
                if match:              # If only a single regex was passed in, return the data if it is found
                    if not incl:
                        data = data.replace(match.group(0),"") # Will replace the match with a blank string
                    self.before = data
                    self.matched = regex
                    return data

    '''
    The expectnl method just calls self.expect('\n',incl=False)
    '''
    def expectnl(self):
        return self.expect('\n',incl=False)

    '''
    The interact method makes this into a netcat-like functionality. It will print whatever it receives
    over the socket and send everything you type.

    Optional parameters are:
        delimeter - Specify a delimeter to be appended to all data sent over the socket. Defaults to a '\n'
    '''
    def interact(self, delimiter="\n"):
        try:
            r = self.recieverPrinter(self.socket)
            r.daemon = True # ensure the thread quits when the main thread dies
            r.start() # start the reciever thread
            # enter the send loop
            while True:
                command = raw_input()
                if command == "exit":
                    # die in a pretty manner
                    r.kill()
                    self.socket.sendall(command+delimiter)
                    return
                self.socket.sendall(command+delimiter)
        except KeyboardInterrupt:
            r.kill()
            return
        except:
            pass

    def settimeout(self, timeout):
        self.timeout = timeout

    def start(self, connection_data):
        self.socket = socket.socket()
        self.socket.connect(connection_data)

    def shutdown(self):
        self.socket.close()
        self.socket = None
                        
    class recieverPrinter(threading.Thread):
        def __init__(self, socket):
            super(nexpect.recieverPrinter, self).__init__()
            self.socket = socket
            self.socket.settimeout(0.5)
            self.stop = False
        def run(self):
            while not self.stop:
                try:
                    sys.stdout.write(self.socket.recv(1024))
                    sys.stdout.flush()
                except:
                    pass
        def kill(self):
            self.stop = True


class TimeoutException(Exception): 
    def __init__(self, message=''):
        Exception.__init__(self, message)
