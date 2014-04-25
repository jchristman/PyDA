import socket, nexpect, thread, sys

class PyDAServer:
    def __init__(self, interface, port):
        self.interface = interface
        self.port = port

    def start(self):
        thread.start_new_thread(self.start_chat, ())

    def start_chat(self):
        server = socket.socket()
        server.bind((self.interface, self.port))
        server.listen(1)
        print 'Server started on %s' % str((self.interface, self.port))
        print 'Listening for connections now.'
        try:
            while True:
                client, info = server.accept()
                thread.start_new_thread(self.client_handler, (client,info))
        except:
            chat_server.close()

    def client_handler(self, client, info):
        print 'New connection from %s.' % str(info)
        try:
            client = nexpect.spawn(client)
            while True:
                try:
                    message = client.expectnl() #FIXME and use JSON. We can decipher chat messages from PyDA messages
                    user,data = message.split(':')
                    print '%s : %s' % (user, data)
                except nexpect.TimeoutException: 
                    pass
        except Exception as e:
            client.shutdown()
            print 'Connection from %s closed.' % str(info)
