from settings import *

class Disassembler:
    def load(self, binary):
        self.binary = binary
        for format in IMPORTED_FORMATS:
            try:
                self.dis = format.disassemble(self.binary)
                break
            except:
                print "Nope, not",`format`
        if not self.dis:
            raise UnsupportedBinaryFormatException()

    def disassemble(self):
        return self.dis.disassemble()

class UnsupportedBinaryFormatException(Exception):
    pass
