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
                self.program_info = format.parse_program(self.binary)
                return True
        return False

    def disassemble(self):
        md = Cs(self.program_info['arch'], self.program_info['class'])

        for section in self.program_info['sections_info']:
            section_name = section['sh_name_string']
            CODE = self.binary[section['sh_offset'] : section['sh_offset'] + section['sh_size']]
            for inst in md.disasm(CODE, section['sh_addr']):
                print "%s : 0x%x: %s\t%s\t%s" %(section_name, inst.address,  str(inst.bytes).encode('hex'), inst.mnemonic, inst.op_str)
            raw_input('Finished printing a section. Press enter for the next section.')

if __name__ == '__main__':
    FILENAME = 'test-elfs/secure-safehouse64.elf'
    dis = Disassembler(FILENAME)
    dis.disassemble()
