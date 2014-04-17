class StdoutRedirector:
    def __init__(self, callback):
        self.callback = callback

    def write(self, message):
        self.callback(message)
