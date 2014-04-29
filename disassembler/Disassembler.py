from settings import *

class Disassembler:
    def load(self, binary):
        self.binary = binary
        for format in IMPORTED_FORMATS:
            try:
                self.dis = format.disassemble(self.binary)
                break
            except:
                print 'File header did not match %s' % format.FILETYPE_NAME
        if not self.dis:
            raise UnsupportedBinaryFormatException()

    def getFileType(self):
        return self.dis.FILETYPE_NAME

    def disassemble(self):
        return self.dis.disassemble()

class UnsupportedBinaryFormatException(Exception):
    pass
