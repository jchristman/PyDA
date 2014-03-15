from capstone import *
from settings import *

class Disassembler:
    def __init__(self, filename):
        self.binary = open(filename,'rb').read()
        found = self.get_program_info()
        if not found:
            print 'File is not a known file type. The magic header did not match anything in the supported formats.'
            exit()

    def get_program_info(self):
        for format in IMPORTED_FORMATS:
            if self.binary[format.MagicHeader.offset : format.MagicHeader.offset + format.MagicHeader.size] == format.MagicHeader.value:
                self.header_info = format.parse_program(self.binary)
                return True
        return False

    def disassemble(self):
        CODE = self.binary[self.header_info['code_offset'] : self.header_info['code_offset'] + self.header_info['code_size']]
        print CODE[:16].encode('hex'), self.header_info['code_offset'], self.header_info['code_size']
        return
        md = Cs(self.header_info['arch'], self.header_info['class'])
        for inst in md.disasm(CODE, self.header_info['entry_point']):
            print "0x%x: %s\t%s\t%s" %(inst.address,  str(inst.bytes).encode('hex'), inst.mnemonic, inst.op_str)

if __name__ == '__main__':
    FILENAME = 'test-elfs/keygenme32.elf'
    dis = Disassembler(FILENAME)
    dis.disassemble()
