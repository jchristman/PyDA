import struct, re
import sys
from disassembler.formats.helpers.label import Label
from disassembler.formats.helpers import asmfeatures
from disassembler.formats.helpers.stringfinder import StringFinder
from disassembler.formats.helpers.comparators import InstComparator, AddressComparator, MnemonicComparator, OpStrComparator, BytesComparator, CommentComparator
from disassembler.formats.helpers.comparators import LabelComparator, LabelAddressComparator, LabelNameComparator, LabelItemComparator
from disassembler.formats.helpers.addressrangemanager import AddressRangeManager
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
        self.strings = {}
        self.labels = {}
        self.string_rep = []

    ### ADDING FUNCS ###
    def addInst(self, inst):
        if isinstance(inst, CommonInstFormat):
            self.instructions.append(inst)

    def addFunction(self, start_index, end_index, name):
        func = CommonFunctionFormat(start_index, end_index, name, self)
        self.functions.append(func)
    
    def addLabel(self, address, name, item, xrefs=None):
        self.labels[address] = Label(address, name, item, xrefs)
    
    def addStringLabels(self):
        for addr in self.strings.keys():
            self.addLabel(addr, self.strings[addr].name, self.strings[addr])

    def addFunctionLabels(self):
        for func in self.functions:
            self.addLabel(func.start_address, func.name, func)

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
                    self.addFunction(function_start, i, self.name + '_func_%i' % len(self.functions))

        # Tidy up uncompleted functions
        if not looking_for_prologue:
            self.addFunction(function_start, len(self.instructions)-1, self.name+'_func_%i' % len(self.functions))
        
    def searchForStrings(self):
        bytes = self.getBytes()
        sf = StringFinder(self.virtual_address, bytes)
        self.strings = sf.findStrings(length=self.program.MIN_STRING_SIZE)
    
    def sort(self):
        self.instructions = sorted(self.instructions, key=lambda x: x.address)
        self.functions = sorted(self.functions, key=lambda x: x.start_address)
        # self.strings = [self.strings[k] for k in sorted(self.strings, key=self.strings.get, reverse=True)]
        return self

    def searchObject(self, string):
        '''
        This function will return the object represented by the given string.
        '''
        pass

    def searchIndex(self, string):
        '''
        This function will return the index of the given string in the data model.
        '''
        pass
    
    def search(self, string):
        '''
        This function will return the index of the found object, as well
        as some representation of the string input in a format
        that the search function will understand - a CommonInstFormat
        '''
        m = re.search(r'0x([a-fA-F0-9]+)', string)
        if m:
            result = self._search(AddressComparator(CommonInstFormat(int(m.group(0), 16), None, None, None, None)))
            return result

    def _search(self, inst_comparator):
        if inst_comparator is None: 
            return None
        if not isinstance(inst_comparator, InstComparator):
            raise ImproperParameterException('Search method only accepts InstComparator as a parameter')
        if inst_comparator in self.instructions:
            match = inst_comparator.match
            # print 'match is:',[match.address, match.mnemonic, match.op_str]
            # If the address mnemonic and op_str are in this line then we found it
            features = ['0x%x' % match.address, match.mnemonic, match.op_str]
            # print 'features:',features
            for index, line in enumerate(self.string_rep):
                # print 'line', line
                if all(x in line for x in features):
                    return (index, match)
        return None

    def getLabelIndex(self, name):
        result = self._getLabelIndex(LabelNameComparator(Label(None, name, None)))
        return result

    def _getLabelIndex(self, label_comparator):
        if label_comparator is None: 
            return None
        if not isinstance(label_comparator, LabelComparator):
            raise ImproperParameterException('Search method only accepts LabelComparator as a parameter')
        if label_comparator in self.labels.values():
            match = label_comparator.match
            for index, line in enumerate(self.string_rep):
                if match.name + ':' in line: # all label declarations end in a ":"
                    return index
        return None

    def serialize(self, start_index=0, end_index=None):
        rep = ''
        # print 'start/end:',[start_index, end_index]
        if not self.flags.execute:
            rep = CommonDataSectionFormat.toString(self, start_index, end_index)
        else:
            rep = CommonExecutableSectionFormat.toString(self, start_index, end_index)

        curr = self.string_rep
        if end_index is None:
            curr[start_index:] = rep
        else:
            curr[start_index:end_index] = rep
        self.string_rep = curr

        # print 'rep is now:',''.join([x for x in self.string_rep[0:15]])

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
    def toString(section, start_index=0, end_index=None): # TODO: These could use a start and end index to speed things up, but that's an optimization thing.
        '''
        Accessible as a static method. CommonSectionFormat.toString(section)
        '''
        string_array = []
        if end_index is None:
            end_index = sys.maxint

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


        # TODO: verify the efficiency of this
        # Logic to support start and end indices 
        current_size = len(string_array)-1
        if start_index >= current_size:
            string_array = []
        line_count = current_size

        for inst in section.instructions:
            data = ''
            if inst.address in section.labels:
                line_count += len(section.labels[inst.address])
                if start_index <= line_count < end_index: # only add the line if we want it
                    data += section.labels[inst.address].toString(
                        section.program.PYDA_BEGL,
                        section.program.PYDA_SECTION, section.name, 
                        section.program.PYDA_ADDRESS, section.program.PYDA_LABEL,
                        section.program.PYDA_ENDL)
                    

            line_count += 1
            if start_index <= line_count < end_index: # only add the line if we want it
                data += inst.toString(
                        section.program.PYDA_BEGL,
                        section.program.PYDA_SECTION, section.name, 
                        section.program.PYDA_ADDRESS, 
                        section.program.PYDA_BYTES, section.program.NUM_OPCODE_BYTES_SHOWN, 
                        section.program.PYDA_MNEMONIC,
                        section.program.PYDA_OP_STR,
                        section.program.PYDA_COMMENT,
                        section.program.PYDA_ENDL
                        )

            string_array += [string + '\n' for string in data.split('\n') if not string == '']

        if len(section.instructions) > 0 and end_index == sys.maxint:
            string_array += ['\n']

        return string_array

class CommonDataSectionFormat(CommonSectionFormat):
    '''
    These are here to know how to convert them to strings. Otherwise, they
    are just CommonSectionFormat object
    '''
    @staticmethod
    def toString(section, start_index=0, end_index=None):
        '''
        Accessible as a static method. CommonDataSectionFormat.toString(section)
        '''
        string_array = []
        if end_index is None:
            end_index = sys.maxint

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

        # TODO: verify the efficiency of this
        # Logic to support start and end indices 
        current_size = len(string_array)
        if start_index >= current_size:
            string_array = []
        line_count = current_size


        bytes = section.getBytes()
        index = 0
        while index < len(bytes):
            data = ''
            current_addr = index + section.virtual_address

            if current_addr in section.strings:
                line_count += 1
                if start_index <= line_count < end_index: # only add the line if we want it
                    data += '%s%s: %s0x%x%s\n' % (
                        section.program.PYDA_SECTION, section.name,
                        section.program.PYDA_ADDRESS, current_addr,
                        section.program.PYDA_ENDL) # Empty newline

                line_count += 1
                if start_index <= line_count < end_index: # only add the line if we want it
                    data += '%s%s: %s0x%x%s %s %s\n' % (
                        section.program.PYDA_SECTION, section.name,
                        section.program.PYDA_ADDRESS, current_addr,
                        section.program.PYDA_LABEL, section.labels[current_addr].name + ":",
                        section.program.PYDA_ENDL)

                # Then, write the string itself
                the_string = section.strings[current_addr]
                string_contents = the_string.contents[:-1] if '\x00' in the_string.contents else the_string.contents # get rid of trailing null bytes in the string.
                
                line_count += 1
                if start_index <= line_count < end_index: # only add the line if we want it
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
                line_count += 1
                if start_index <= line_count < end_index: # only add the line if we want it
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
