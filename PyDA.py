from interface import App
from disassembler.Disassembler import Disassembler
from server.PyDAServer import PyDAServer

class PyDA:
    def __init__(self):
        dis = Disassembler()
        server = PyDAServer('0.0.0.0',9000)
        app.build_and_run(dis, server)

if __name__ == '__main__':
    pyda = PyDA()
