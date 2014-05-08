import struct
from disassembler.formats.helpers.label import Label
from disassembler.formats.helpers.models import DataModel
from disassembler.formats.helpers import asmfeatures
from disassembler.formats.helpers.stringfinder import StringFinder
from disassembler.formats.common.inst import CommonInstFormat
from disassembler.formats.common.function import CommonFunctionFormat

# TODO: change all string formats (with the PYDA vars) to a one time, upfront operation
# so that we don't have to do it every time. This should save quite a few clock cycles.

class CommonSectionFormat:
    def __init__(self, program, section_name, architecture, mode, vaddr, flags, bytes = None):
        self.program = program
        self.name = section_name
        self.arch = architecture
        self.mode = mode
        self.flags = flags
        self.bytes = None
        if not self.flags.execute:
            self.bytes = bytes # Bytes will only be set when this is a non-exec section
        self.virtual_address = vaddr
        self.instructions = DataModel([], toFunc=CommonInstFormat.toString, lengthFunc=CommonInstFormat.length)
        self.functions = DataModel([], toFunc=CommonFunctionFormat.toString, lengthFunc=CommonFunctionFormat.length)
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
        bytes = self.getBytes()
        sf = StringFinder(self.virtual_address, bytes)
        self.strings = sf.findStrings()

    def sort(self):
        self.instructions = sorted(self.instructions, key=lambda x: x.address)
        self.functions = sorted(self.functions, key=lambda x: x.start_address)
        self.strings = sorted(self.strings, key=lambda x: x.address)
        return self

    def getBytes(self): # TODO: Have Frank explain the necessity of this.
        if self.flags.execute:
            bytes = bytearray()
            for inst in self.instructions:
                bytes.extend(inst.bytes)
            return bytes
        else:
            return self.bytes

class CommonDataSectionFormat(CommonSectionFormat):
    '''
    These are here to know how to convert them to strings. Otherwise, they
    are just CommonSectionFormat object
    '''
    @staticmethod
    def length(section):
        return 8 + int(1.02*len(section.getBytes())) # TODO: fix this estimate of the length

    @staticmethod
    def toString(section): # TODO: These could use a start and end index to speed things up, but that's an optimization thing.
        '''
        Accessible as a static method. CommonDataSectionFormat.toString(section)
        '''
        fields = {
            "Section name": section.name,
            "Properties": str(section.flags),
            "Starting Address" : "0x%x" % section.virtual_address,
            "Size": str(len(section.getBytes())) + " bytes",
        }

        max_length = max(len(x) + len(fields[x]) for x in fields) + 2

        section_info = "#"*(max_length+3) + "\n"
        section_info += "   SECTION START\n"
        for x in fields:
            section_info += ("   {:<%d}\n" % max_length).format(x + ": " + fields[x])
        section_info += "#"*(max_length+3) + "\n \n"

        for line in section_info.split('\n'):
            yield line + '\n'

        bytes = section.getBytes()
        index = 0
        while index < len(bytes):
            data = ''
            current_addr = index + section.virtual_address

            if current_addr in section.strings:
                data += '%s%s: %s0x%x%s\n' % (
                    section.program.PYDA_SECTION, section.name,
                    section.program.PYDA_ADDRESS, current_addr,
                    section.program.PYDA_ENDL) # Empty newline

                ''' No labels yet
                data += '%s%s: %s0x%x%s %s %s\n' % (
                    section.program.PYDA_SECTION, section.name,
                    section.program.PYDA_ADDRESS, current_addr,
                    section.program.PYDA_LABEL, section.findLabelByAddress(current_addr).name + ":",
                    section.program.PYDA_ENDL)'''

                # Then, write the string itself
                the_string = section.strings[current_addr]
                string_contents = the_string.contents[:-1] if '\x00' in the_string.contents else the_string.contents # get rid of trailing null bytes in the string.
                data += "%s%s: %s0x%x \t %s %s \t %s db %s '%s',0 %s\n" % (
                    section.program.PYDA_SECTION, section.name,
                    section.program.PYDA_ADDRESS, current_addr,
                    section.program.PYDA_BYTES, the_string.getByteString(section.program.NUM_OPCODE_BYTES_SHOWN),
                    section.program.PYDA_MNEMONIC, section.program.PYDA_COMMENT, string_contents,
                    section.program.PYDA_ENDL)
                
                index += len(string_contents)

            #Otherwise, just mark it as a byte
            else:
                byte = bytes[index].encode("hex")
                data += "%s%s: %s0x%x \t %s %s \t %s db %s '%s' %s\n" % (
                    section.program.PYDA_SECTION, section.name,
                    section.program.PYDA_ADDRESS, current_addr,
                    section.program.PYDA_BYTES, byte,
                    section.program.PYDA_MNEMONIC, section.program.PYDA_COMMENT,
                    byte, section.program.PYDA_ENDL)
                index += 1

            yield data

        yield ' \n'

class CommonExecutableSectionFormat(CommonSectionFormat):
    '''
    These are here to know how to convert them to strings. Otherwise, they
    are just CommonExecutableSectionFormat object
    '''
    @staticmethod
    def length(section):
        return 9 + len(section.instructions) + 1 # The length of the header in lines

    @staticmethod
    def toString(section):
        '''
        Accessible as a static method. CommonSectionFormat.toString(section)
        '''
        fields = {
            "Section name": section.name,
            "Properties": str(section.flags),
            "Starting Address" : "0x%x" % section.virtual_address,
            "Number of Functions": str(len(section.functions)),
            "Size": str(len(section.getBytes())) + " bytes",
        }

        max_length = max(len(x) + len(fields[x]) for x in fields) + 2

        section_info = "#"*(max_length+3) + "\n"
        section_info += "   SECTION START\n"
        for x in fields:
            section_info += ("   {:<%d}\n" % max_length).format(x + ": " + fields[x])
        section_info += "#"*(max_length+3) + "\n \n"

        for line in section_info.split('\n'):
            yield line + '\n'

        for inst in section.instructions:
            yield '%s%s: %s0x%x \t %s%s \t %s%s  %s%s  %s%s %s\n' % (
                    section.program.PYDA_SECTION, section.name, 
                    section.program.PYDA_ADDRESS, inst.address,
                    section.program.PYDA_BYTES, inst.getByteString(section.program.NUM_OPCODE_BYTES_SHOWN), 
                    section.program.PYDA_MNEMONIC, inst.mnemonic, 
                    section.program.PYDA_OP_STR, inst.op_str,
                    section.program.PYDA_COMMENT, inst.comment,
                    section.program.PYDA_ENDL
                    )
            
        yield ' \n' # Yield one last new line for spacing


'''
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

            yield data'''
