from capstone import Cs
from settings import *

class Disassembler:
    def load(self, binary):
        self.binary = binary
        for format in IMPORTED_FORMATS:
            self.dis = format.disassemble(self.binary)
        if not self.dis:
            raise UnsupportedBinaryFormatException()

    def disassemble(self):
        md = Cs(self.dis.arch, self.dis.bin_class)
        disassembly = ''
        for section in self.dis.sections:
            section_name = section.sh_name_string
            CODE = self.binary[section.sh_offset : section.sh_offset + section.sh_size]
            
            for inst in md.disasm(CODE, section.sh_addr):
                disassembly += "%s : 0x%x: %s\t%s\n" %(section_name, inst.address, inst.mnemonic, inst.op_str)
            disassembly += '\n'
        return disassembly

class UnsupportedBinaryFormatException(Exception):
    pass
