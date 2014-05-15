import struct, re
from disassembler.formats.helpers.label import Label
from disassembler.formats.helpers import asmfeatures
from disassembler.formats.helpers.stringfinder import StringFinder
from disassembler.formats.helpers.comparators import InstComparator, AddressComparator, MnemonicComparator, OpStrComparator, BytesComparator, CommentComparator
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
        self.instructions = []
        self.functions = []
        self.labels = {}
        self.functions_reverse_lookup = {}

        self.string_rep = []

    ### ADDING FUNCS ###
    def addInst(self, inst):
        if isinstance(inst, CommonInstFormat):
            self.instructions.append(inst)

    def addFunction(self, start_index, end_index, name):
        func = CommonFunctionFormat(start_index, end_index, name, self)
        self.functions.append(func)
        self.functions_reverse_lookup[func.start_address] = func
    
    def addLabel(self, address, name, window_location=None, xrefs=None):
        self.labels[address] = Label(address, name, window_location, xrefs)
    
    def addStringLabels(self):
        for addr in self.strings.keys():
            self.addLabel(addr, self.strings[addr].name)

    def addFunctionLabels(self):
        for func in self.functions:
            self.addLabel(func.start_address, func.name)

    ### SEARCH FUNCS ###
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
        self.strings = sf.findStrings(length=self.program.MIN_STRING_SIZE)
    
    def sort(self):
        self.instructions = sorted(self.instructions, key=lambda x: x.address)
        self.functions = sorted(self.functions, key=lambda x: x.start_address)
        self.strings_list = [self.strings[k] for k in sorted(self.strings, key=self.strings.get, reverse=True)]
        return self
    
    def search(self, string):
        '''
        This function will return some representation of the string input in a format
        that the search function will understand - a CommonInstFormat.
        '''
        m = re.search(r'0x([a-fA-F0-9]+)', string)
        if m:
            result = self._search(AddressComparator(CommonInstFormat(int(m.group(0), 16), None, None, None, None)))
            return result

    def _search(self, inst_comparator):
        if inst_comparator is None: return None
        if not isinstance(inst_comparator, InstComparator):
            raise ImproperParameterException('Search method only accepts InstComparator as a parameter')
        if inst_comparator in self.instructions:
            match = inst_comparator.match
            return match
            # return self.instructions.index(match)
        return None

    def serialize(self):
        if not self.flags.execute:
            self.string_rep = CommonDataSectionFormat.toString(self)
        else:
            self.string_rep = CommonExecutableSectionFormat.toString(self)

    ### ACCESSOR FUNCS ###
    def getBytes(self): 
        if self.flags.execute:
            bytes = bytearray()
            for inst in self.instructions:
                bytes.extend(inst.bytes)
            return bytes
        else:
            return self.bytes

class CommonExecutableSectionFormat(CommonSectionFormat):
    '''
    These are here to know how to convert them to strings. Otherwise, they
    are just CommonExecutableSectionFormat object
    '''
    @staticmethod
    def toString(section): # TODO: These could use a start and end index to speed things up, but that's an optimization thing.
        '''
        Accessible as a static method. CommonSectionFormat.toString(section)
        '''
        string_array = []

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

        string_array += [string + '\n' for string in section_info.split('\n') if not string == '']

        for inst in section.instructions:
            data = ''
            if inst.address in section.functions_reverse_lookup.keys():
                data += '%s%s: %s0x%x%s\n' % (
                    section.program.PYDA_SECTION, section.name,
                    section.program.PYDA_ADDRESS, inst.address,
                    section.program.PYDA_ENDL) # Empty newline
                data += '%s%s: %s0x%x%s %s %s\n' % (
                    section.program.PYDA_SECTION, section.name,
                    section.program.PYDA_ADDRESS, inst.address,
                    section.program.PYDA_LABEL, section.labels[inst.address].name + ":",
                    section.program.PYDA_ENDL)

            data += '%s%s%s: %s0x%x \t %s%s \t %s%s  %s%s  %s%s %s\n' % (
                    section.program.PYDA_BEGL,
                    section.program.PYDA_SECTION, section.name, 
                    section.program.PYDA_ADDRESS, inst.address,
                    section.program.PYDA_BYTES, inst.getByteString(section.program.NUM_OPCODE_BYTES_SHOWN), 
                    section.program.PYDA_MNEMONIC, inst.mnemonic, 
                    section.program.PYDA_OP_STR, inst.op_str,
                    section.program.PYDA_COMMENT, '' if inst.comment is None else '; %s' % inst.comment,
                    section.program.PYDA_ENDL
                    )

            string_array += [string + '\n' for string in data.split('\n') if not string == '']

        if len(section.instructions) > 0:
            string_array += ['\n']

        return string_array

class CommonDataSectionFormat(CommonSectionFormat):
    '''
    These are here to know how to convert them to strings. Otherwise, they
    are just CommonSectionFormat object
    '''
    @staticmethod
    def toString(section):
        '''
        Accessible as a static method. CommonDataSectionFormat.toString(section)
        '''
        string_array = []

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

        string_array += [string + '\n' for string in section_info.split('\n') if not string == '']

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

                data += '%s%s: %s0x%x%s %s %s\n' % (
                    section.program.PYDA_SECTION, section.name,
                    section.program.PYDA_ADDRESS, current_addr,
                    section.program.PYDA_LABEL, section.labels[current_addr].name + ":",
                    section.program.PYDA_ENDL)

                # Then, write the string itself
                the_string = section.strings[current_addr]
                string_contents = the_string.contents[:-1] if '\x00' in the_string.contents else the_string.contents # get rid of trailing null bytes in the string.
                data += "%s%s%s: %s0x%x \t %s %s \t %s db %s '%s',0 %s\n" % (
                    section.program.PYDA_BEGL,
                    section.program.PYDA_SECTION, section.name,
                    section.program.PYDA_ADDRESS, current_addr,
                    section.program.PYDA_BYTES, the_string.getByteString(section.program.NUM_OPCODE_BYTES_SHOWN),
                    section.program.PYDA_MNEMONIC, section.program.PYDA_COMMENT, string_contents,
                    section.program.PYDA_ENDL)
                
                index += len(string_contents)

            #Otherwise, just mark it as a byte
            else:
                byte = bytes[index].encode("hex")
                data += "%s%s%s: %s0x%x \t %s %s \t %s db %s '%s' %s\n" % (
                    section.program.PYDA_BEGL,
                    section.program.PYDA_SECTION, section.name,
                    section.program.PYDA_ADDRESS, current_addr,
                    section.program.PYDA_BYTES, byte,
                    section.program.PYDA_MNEMONIC, section.program.PYDA_COMMENT,
                    byte, section.program.PYDA_ENDL)
                index += 1

            string_array += [string + '\n' for string in data.split('\n') if not string == '']
        
        if len(bytes) > 0:
            string_array += ['\n']

        return string_array
