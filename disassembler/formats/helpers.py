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
        self.function = None

class CommonFunctionFormat:
    def __init__(self, start_inst_index, end_inst_index, name, parent_section):
        self.name = name
        self.parent_section = parent_section
        self.start_address = self.parent_section.instructions[start_inst_index].address
        self.end_address = self.parent_section.instructions[end_inst_index].address
        self.function_instructions = self.parent_section.instructions[start_inst_index : end_inst_index + 1]
        for inst in self.function_instructions:
            inst.function = self

class CommonSectionFormat:
    def __init__(self, section_name):
        self.name = section_name
        self.instructions = []
        self.functions = []

    def addInst(self, inst):
        if isinstance(inst, CommonInstFormat):
            self.instructions.append(inst)

    def addFunction(self, start_address, end_address, name):
        self.functions.append(CommonFunctionFormat(start_address, end_address, name, self))

    def searchForInstSequence(self, inst_sequence, start_index=0, num_results=-1):
        sequence_indices = []
        for i in xrange(start_index, len(self.instructions) - 2): # Go through the last 2 instructions of this section
            sequence_found = True
            for j in xrange(len(inst_sequence)):
                if self.instructions[i + j].mnemonic == inst_sequence[j].mnemonic:
                    if 'WILDCARD' in inst_sequence[j].op_str:
                        if self.instructions[i + j].op_str.replace('WILDCARD','') == inst_sequence[j].op_str.replace('WILDCARD',''):
                            continue
                    elif self.instructions[i + j].op_str == inst_sequence[j].op_str:
                        continue
                else:
                    sequence_found = False
                    break
            if sequence_found:
                sequence_indices.append(i)
                if num_results == -1:
                    continue
                elif len(sequence_indices) == num_results:
                    break
        if len(sequence_indices) == 0:
            sequence_indices.append(len(self.instructions))
        return sequence_indices

    def searchForFunctions(self):
        prolog_sequence = [CommonInstFormat(None, 'push', 'ebp'), CommonInstFormat(None, 'mov', 'ebp, esp'), CommonInstFormat(None, 'sub', 'esp, WILDCARD')]
        function_inst_indices = self.searchForInstSequence(prolog_sequence)
        for function_index in function_inst_indices:
            if function_index == len(self.instructions):
                break
            epilog_index = self.findFunctionEpilog(function_index)
            self.functions.append(CommonFunctionFormat(function_index, epilog_index, 'func_%i' % len(self.functions), self))

        for function in self.functions:
            print 'Function Found! %s : %s, %08x-%08x' % (function.parent_section.name, function.name, function.start_address, function.end_address)

    def findFunctionEpilog(self, start_inst_index):
        epilog_1 = [CommonInstFormat(None, 'pop', 'ebp'), CommonInstFormat(None, 'ret', '')]
        epilog_2 = [CommonInstFormat(None, 'leave', ''), CommonInstFormat(None, 'ret', '')]
        return min(self.searchForInstSequence(epilog_1, start_inst_index, 1)[0] + 1, self.searchForInstSequence(epilog_2, start_inst_index, 1)[0] + 1)
        
    def sort(self):
        self.instructions = sorted(self.instructions, key=lambda x: x.address)
        self.functions = sorted(self.functions, key=lambda x: x.start_address)
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
