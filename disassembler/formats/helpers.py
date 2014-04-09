import struct

BYTE = 1    # 8 bits
HWORD = 2   # 16 bits
WORD = 4    # 32 bits
DWORD = 8   # 64 bits

class BadMagicHeaderException(Exception):
    pass

class CommonInstFormat:
    def __init__(self, address, mnemonic, op_str):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str

class CommonSectionFormat:
    def __init__(self, section_name):
        self.name = section_name
        self.instructions = []

    def addInst(self, inst):
        if isinstance(inst, CommonInstFormat):
            self.instructions.append(inst)

    def sort(self):
        self.instructions = sorted(self.instructions, key=lambda x: x.address)
        return self

class CommonProgramDisassemblyFormat:
    def __init__(self, program_info):
        self.program_info = program_info
        self.sections = []

    def addSection(self, section):
        if isinstance(section, CommonSectionFormat) and len(section.instructions) > 0:
            self.sections.append(section.sort())

    def sort(self):
        self.sections = sorted(self.sections, key=lambda x: x.instructions[0].address)

    def toString(self):
        self.sort()
        string = self.program_info
        
        for section in self.sections:
            string += '\n------------------------------------------------------\n'
            string += '\tSection Name: %s\n\n' % section.name
            for inst in section.instructions:
                string += '%s - 0x%08x:\t%s\t%s\n' % (section.name, inst.address, inst.mnemonic, inst.op_str)

        return string
