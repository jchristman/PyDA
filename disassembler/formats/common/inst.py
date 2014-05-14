import struct
from disassembler.formats.helpers.label import Label

class CommonInstFormat:
    def __init__(self, address, mnemonic, op_str, bytes, comment=None):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.bytes = bytes
        self.function = None
        self.comment = comment

    def getByteString(self, num_bytes):
        string_size = num_bytes*3
        unpadded = str(self.bytes).encode("hex")[0:num_bytes*2]
        return ' '.join([unpadded[x:x+2] for x in xrange(0, len(unpadded), 2)]).ljust(string_size)

    @staticmethod
    def length(inst):
        return 1

    @staticmethod
    def toString(inst):
        pass
