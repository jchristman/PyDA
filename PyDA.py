from interface import PyDAInterface
from disassembler.Disassembler import Disassembler

class PyDA:
    def __init__(self):
        dis = Disassembler()
        PyDAInterface.build_and_run(dis)

if __name__ == '__main__':
    pyda = PyDA()
