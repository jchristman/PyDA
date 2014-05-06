import struct
from disassembler.formats.helpers.label import Label

class BadMagicHeaderException(Exception):
    pass

class CommonProgramDisassemblyFormat:
    def __init__(self, program_info):
        self.program_info = program_info
        self.sections = []
        self.functions = []
        self.strings = []
        self.labels = set()

    def addSection(self, section):
        if isinstance(section, CommonSectionFormat):
            if section.flags.execute:
                section.searchForFunctions()
                self.functions += section.functions
                self.addLabelsForFunctions(section.functions)

            section.searchForStrings()
            self.strings += section.strings
            self.addLabelsForStrings(section.strings)

            self.sections.append(section.sort())

    def addLabel(self, address, name, window_location=None, xrefs=None):
        self.labels.add(Label(address, name, window_location, xrefs))

    def addLabelsForStrings(self, strings):
        for x in strings:
            self.addLabel(x.address, x.name)

    def addLabelsForFunctions(self, functions):
        for x in functions:
            self.addLabel(x.start_address, x.name)

    def printLabels(self):
        with open("test.out","w+") as f:
            for l in self.labels:
                f.write("0x%x - %s\n" % (l.address, l.name))


    def findLabelByAddress(self, address):
        #TODO: Find a more efficient way of doing this
        return [x for x in self.labels if x.address == address][0]

    def findStringByAddress(self, address):
        #TODO: Find a more efficient way of doing this
        return [x for x in self.strings if x.address == address][0]

    def getSectionByName(self, name):
        for section in self.sections:
            if section.name == name:
                return section
        return None

    def getExecutableSections(self):
        return [x for x in self.sections if x.flags.execute]

    def getDataSections(self):
        return [x for x in self.sections if not x.flags.execute]

    def sort(self):
        have_instructions = [x for x in self.sections if len(x.instructions) > 0]
        no_instructions = [x for x in self.sections if len(x.instructions) == 0]
        self.sections = sorted(have_instructions, key=lambda x: x.instructions[0].address) + no_instructions

    def getLines(self, section, num_opcode_bytes, start=None, end=None):
        label_addresses = set([label.address for label in self.labels])
        if start is None:
            start = 0
        if end is None:
            end = len(section.instructions)
        for inst in section.instructions[start : end]:
            data = ''
            #Check if this is the start of a label
            if inst.address in label_addresses: 
                data += 'P_S%s: P_A0x%xP_N\n' % (section.name, inst.address) # Empty newline
                data += 'P_S%s: P_A0x%xP_L %s P_N\n' % (section.name, inst.address, self.findLabelByAddress(inst.address).name + ":")

            # Write the instruction
            if inst.comment is not None:
                data += 'P_S%s: P_A0x%x \t P_B%s \t P_M%s  P_O%s  ; P_C%s P_N\n' % (section.name, inst.address, inst.getByteString(num_opcode_bytes), inst.mnemonic, inst.op_str, inst.comment)
            else:
                data += 'P_S%s: P_A0x%x \t P_B%s \t P_M%s  P_O%s P_N\n' % (section.name, inst.address, inst.getByteString(num_opcode_bytes), inst.mnemonic, inst.op_str)

            yield data, inst.function

    def getDataLines(self, section, num_opcode_bytes, start=None, end=None):
        string_addresses = set([string.address for string in self.strings])
        bytes = section.getBytes()
        if start is None:
            start = 0
        if end is None:
            end = len(section.bytes) 

        index = start
        while index < end:
            data = ''
            current_addr = index + section.virtual_address

            #If it's a string, mark it as such
            if current_addr in string_addresses: 
                # First, write the label
                data += 'P_S%s: P_A0x%xP_N\n' % (section.name, current_addr) # Empty newline
                data += 'P_S%s: P_A0x%xP_L %s P_N\n' % (section.name, current_addr, self.findLabelByAddress(current_addr).name + ":")

                # Then, write the string itself
                the_string = self.findStringByAddress(current_addr)
                if "\x00" in the_string.contents: # Basic trailing null-byte issue prevention
                    data += "P_S%s: P_A0x%x \t P_B %s \t P_M db P_C '%s',0 P_N\n" % (section.name, current_addr, the_string.getByteString(num_opcode_bytes), the_string.contents[:-1])
                else:
                    data += "P_S%s: P_A0x%x \t P_B %s \t P_M db P_C '%s' P_N\n" % (section.name, current_addr, the_string.getByteString(num_opcode_bytes), the_string.contents)
                
                index += len(the_string.contents)

            #Otherwise, just mark it as a byte
            else:
                byte = bytes[index].encode("hex")
                data += "P_S%s: P_A0x%x \t P_B %s \t P_M db P_C '%s' P_N\n" % (section.name, current_addr, byte, byte)
                index += 1

            yield data

    def serialize(self):
        self.sort()
        data = []
        
        for section in self.sections:
            # This variable will save us some run time by keeping track of which function we just placed in the text
            current_func_index = 0
            func_started = False

            #print 'Parsing new section.\n    Section Name: %s\n    Number of functions in section: %i' % (section.name, len(section.functions))

            for inst in section.instructions:
                if not section.flags.execute:
                    continue
                try:
                    if not func_started and inst.address == section.functions[current_func_index].start_address:
                        func_started = True
                except:
                    pass # We don't have any more functions
                
                if inst.mnemonic == 'call':
                    try:
                        func_addr = int(inst.op_str, 16)
                        func = section.functions_reverse_lookup[func_addr]
                        inst.op_str = func.name
                    except:
                        pass # We didn't find the function or the conversion to an int failed
                
                data.append((section.name, inst.address, inst.mnemonic, inst.op_str, inst.function))
                
                if func_started and inst.address == section.functions[current_func_index].end_address:
                    func_started = False
                    current_func_index += 1

        return data


class CommonSectionFormat:
    def __init__(self, section_name, architecture, mode, vaddr, flags, bytes = None):
        self.name = section_name
        self.arch = architecture
        self.mode = mode
        self.flags = flags
        self.bytes = None
        if not self.flags.execute:
            self.bytes = bytes # Bytes will only be set when this is a non-exec section
        self.virtual_address = vaddr
        self.instructions = []
        self.functions = []
        self.functions_reverse_lookup = {}

    def addInst(self, inst):
        if isinstance(inst, CommonInstFormat):
            self.instructions.append(inst)

    def addFunction(self, start_index, end_index, name):
        func = CommonFunctionFormat(start_index, end_index, name, self)
        self.functions.append(func)
        self.functions_reverse_lookup[func.start_address] = func

    def doesInstSequenceMatch(self, inst_sequence, disass_index):
            # Check if the sequence is even possible
            if disass_index + len(inst_sequence) >= len(self.instructions):
                return False 

            for j in xrange(len(inst_sequence)):
                if self.instructions[disass_index + j].mnemonic == inst_sequence[j].mnemonic:
                    if 'WILDCARD' in inst_sequence[j].op_str:
                        if self.instructions[disass_index + j].op_str.replace('WILDCARD','') == inst_sequence[j].op_str.replace('WILDCARD',''):
                            continue
                    elif self.instructions[disass_index + j].op_str == inst_sequence[j].op_str:
                        continue
                else:
                    return False
            return True

    def searchForInstSequence(self, inst_sequence, start_index=0, num_results=-1):
        sequence_indices = []
        for i in xrange(start_index, len(self.instructions)):
            sequence_found = self.doesInstSequenceMatch(self, inst_sequence, i)
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
        from helpers import asmfeatures
        looking_for_prologue = True
        function_start = 0
        for i in xrange(len(self.instructions)):
            if looking_for_prologue:
                # Check if there is a valid prologue sequence starting at this index
                if True in [self.doesInstSequenceMatch(prologue_seq, i) for prologue_seq in asmfeatures.prologues[self.arch][self.mode]]:
                    looking_for_prologue = False
                    function_start = i
            else:
                if True in [self.doesInstSequenceMatch(epilogue_seq, i) for epilogue_seq in asmfeatures.epilogues[self.arch][self.mode]]:
                    looking_for_prologue = True
                    self.addFunction(function_start, i, 'func_%i' % len(self.functions))

        # Tidy up uncompleted functions
        if not looking_for_prologue:
            self.addFunction(function_start, len(self.instructions)-1, 'func_%i' % len(self.functions))
        
    def searchForStrings(self):
        from helpers.stringfinder import StringFinder
        bytes = self.getBytes()
        sf = StringFinder(self.virtual_address, bytes)
        self.strings = sf.findStrings()

    def sort(self):
        self.instructions = sorted(self.instructions, key=lambda x: x.address)
        self.functions = sorted(self.functions, key=lambda x: x.start_address)
        self.strings = sorted(self.strings, key=lambda x: x.address)
        return self

    def getBytes(self):
        if self.flags.execute:
            bytes = bytearray()
            for inst in self.instructions:
                bytes.extend(inst.bytes)
            return bytes
        else:
            return self.bytes

    def getSectionInfo(self):
        fields = {
            "Section name": self.name,
            "Properties": str(self.flags),
            "Starting Address" : "0x%x" % self.virtual_address,
            "Number of Functions": str(len(self.functions)),
            "Size": str(len(self.getBytes())) + " bytes",
        }

        max_length = max(len(x) + len(fields[x]) for x in fields) + 2

        section_info = "#"*(max_length+3) + "\n"
        section_info += "   SECTION START\n"
        for x in fields:
            section_info += ("   {:<%d}\n" % max_length).format(x + ": " + fields[x])
        section_info += "#"*(max_length+3) + "\n"

        return section_info

class CommonFunctionFormat:
    def __init__(self, start_inst_index, end_inst_index, name, parent_section):
        self.name = name
        self.parent_section = parent_section
        self.start_address = self.parent_section.instructions[start_inst_index].address
        self.end_address = self.parent_section.instructions[end_inst_index].address
        self.function_instructions = self.parent_section.instructions[start_inst_index : end_inst_index + 1]
        for inst in self.function_instructions:
            inst.function = self


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