from capstone import Cs
from settings import *

class Disassembler:
    def get_options(self, binary):
        options = {}
        for format in IMPORTED_FORMATS:
            if binary[format.MagicHeader.offset : format.MagicHeader.offset + format.MagicHeader.size] == format.MagicHeader.value:
                options = format.parse_program(binary)
                return options
        return False

    def disassemble(self, binary, options):
        md = Cs(options['arch'], options['class'])

        disassembly = ''
        for section in options['sections_info']:
            section_name = section['sh_name_string']
            CODE = binary[section['sh_offset'] : section['sh_offset'] + section['sh_size']]
            
            for inst in md.disasm(CODE, section['sh_addr']):
                disassembly += "%s : 0x%x: %s\t%s\n" %(section_name, inst.address, inst.mnemonic, inst.op_str)
            disassembly += '\n'
        return disassembly
