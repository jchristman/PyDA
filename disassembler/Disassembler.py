from settings import *

class Disassembler:
    def load(self, binary):
        self.binary = binary
        for format in IMPORTED_FORMATS:
            self.dis = format.disassemble(self.binary)
        if not self.dis:
            raise UnsupportedBinaryFormatException()

    def disassemble(self):
        return self.dis.disassemble()

class UnsupportedBinaryFormatException(Exception):
    pass
