import struct
import re
from disassembler.formats.helpers.label import Label
from disassembler.formats.helpers.models import AbstractDataModel
from disassembler.formats.common.section import CommonSectionFormat, CommonExecutableSectionFormat, CommonDataSectionFormat
from disassembler.formats.common.inst import CommonInstFormat

class CommonProgramDisassemblyFormat(AbstractDataModel):
    '''
    All the CommonProgramDisassemblyFormat will do now is have an array of Data Models
    that will be used to access and mutate the information in the data structure.
    '''
    def __init__(self, program_info, settings_manager):
        self.program_info = [line + '\n' for line in program_info.split('\n')]
        self.settings_manager = settings_manager

        self.initVars()

        self.executable_sections = []
        self.data_sections = []

        self.header_length = self.getHeaderLength()

    def initVars(self):
        self.PYDA_SECTION = self.settings_manager.get('context','pyda-section')
        self.PYDA_ADDRESS = self.settings_manager.get('context', 'pyda-address')
        self.PYDA_MNEMONIC = self.settings_manager.get('context', 'pyda-mnemonic')
        self.PYDA_OP_STR = self.settings_manager.get('context', 'pyda-op-str')
        self.PYDA_COMMENT = self.settings_manager.get('context', 'pyda-comment')
        self.PYDA_LABEL = self.settings_manager.get('context', 'pyda-label')
        self.PYDA_BYTES = self.settings_manager.get('context', 'pyda-bytes')
        self.PYDA_GENERIC = self.settings_manager.get('context', 'pyda-generic')
        self.PYDA_BEGL = self.settings_manager.get('context', 'pyda-begl')
        self.PYDA_ENDL = self.settings_manager.get('context', 'pyda-endl')
        self.NUM_OPCODE_BYTES_SHOWN = self.settings_manager.getint('disassembly','num-opcode-bytes-shown')
        self.MIN_STRING_SIZE = self.settings_manager.getint('disassembly','min-string-size')

    def addSection(self, section):
        if isinstance(section, CommonSectionFormat):
            section.serialize() # This creates a string representation.
            if section.flags.execute:   self.executable_sections.append(section)
            else:                       self.data_sections.append(section)
    
    def getExecutableSections(self):
        '''
        Return the data model
        '''
        return self.executable_sections

    def getDataSections(self):
        '''
        Return the data model
        '''
        return self.data_sections

    def getFuncs(self):
        funcs = []
        ex_secs = self.getExecutableSections()
        for sec in ex_secs:
            if isinstance(sec, CommonSectionFormat):
                funcs += sec.functions

        return funcs

    def getStrings(self):
        strings = []

        secs = self.getExecutableSections() + self.getDataSections()
        for sec in secs:
            if isinstance(sec, CommonSectionFormat):
                strings += sec.strings.values()

        return strings

    def getSectionWithIndex(self, sections, index):
        offset = self.header_length
        if index < offset:
            return None
        
        for sec in sections:
            offset += len(sec.string_rep)
            if index < offset:
                return sec

        return None

    def serializeRange(self, start, end, key):
        # print 'overall range:', [start, end]
        sections = None
        if key == 'exe':
            sections = self.executable_sections
        elif key == 'data':
            sections = self.data_sections
        else:
            return None

        offset_s = start
        offset_s -= self.header_length
        offset_e = end
        offset_e -= self.header_length
        for sec in sections:
            if offset_s < 0:
                return
            if offset_s > len(sec.string_rep):
                offset_s -= len(sec.string_rep)
                offset_e -= len(sec.string_rep)
                continue
            # print 'serializing:', [sec.name, offset_s, offset_e]
            sec.serialize(offset_s, offset_e)
            offset_s -= len(sec.string_rep)
            offset_e -= len(sec.string_rep)


    def get(self, arg1, arg2=None, arg3=1, key=None):
        if arg2 is None:
            arg2 = arg1
            arg1 = 0
        text_range = xrange(arg1, arg2, arg3)
        for i in text_range:
            if key == 'exe':
                yield self._get(i, self.executable_sections)
            elif key == 'data':
                yield self._get(i, self.data_sections)

    def _get(self, index, section_array):
        offset = 0
        for line in self.program_info:
            if index == offset:
                return line
            offset += 1
        for section in section_array:
            length = len(section.string_rep)
            if index < offset + length: # Then the item is inside this section
                return section.string_rep[index - offset]
            offset += length
        return None

    def getitem(self, index, key=None):
        if index < len(self.text):
            if key == 'exe':
                return self._get(index, self.executable_sections)
            elif key == 'data':
                return self._get(index, self.data_sections)
        else:
            return None
    '''
    These three methods will currently raise a NotImplementedError
    def set(self, index, item, key=None):
        self.text[index] = item
    '''

    def search(self, string, key=None, index=None):
        # print "searching for: ", [string, key, index]
        sections = None
        if key == 'exe':
            sections = self.executable_sections
        elif key == 'data':
            sections = self.data_sections
        else: 
            return None

        if index is None:
            return self._search(string, sections)
        else:
            return self._searchWithIndex(string, sections, index)

    def _search(self, string, sections):
        offset = self.header_length
        for section in sections:
            result = section.search(string)
            if result:
                index, obj = result
                return (index + offset, obj)
            offset += len(section.string_rep)
        return None

    def _searchWithIndex(self, string, sections, index):
        offset = self.header_length
        if index < offset:
            return None

        for section in sections:
            temp = offset + len(section.string_rep)
            if index < temp: # then index is in this section
                result = section.search(string)
                # print 'result',result
                if result:
                    ind, obj = result
                    return (ind + offset, obj)
                else:
                    # The above should always return something. Error otherwise
                    print 'Object was not found in this section for some reason'
                    raise Exception
                break
            offset = temp

        return None

    def searchIndex(self, string):
        '''
        This function will return the index of the given string in the data model.
        '''
        for index, line in enumerate(self.string_rep):
            if line == string:
                return index 

    def length(self, key=None):
        if key == 'exe':
            return self.header_length + sum(len(section.string_rep) for section in self.executable_sections)
        elif key == 'data':
            return self.header_length + sum(len(section.string_rep) for section in self.data_sections)
        else: 
            return 0

    def getLabelIndex(self, name, key=None):
        if key == 'exe':
            return self._getLabelIndex(name, self.executable_sections)
        elif key == 'data':
            return self._getLabelIndex(name, self.data_sections)
        return None

    def _getLabelIndex(self, name, sections):
        offset = self.header_length
        for section in sections:
            result = section.getLabelIndex(name)
            if result:
                return result + offset
            offset += len(section.string_rep)
        return None

    def renderSection(self, s):
        s.serialize()

    def getHeaderLength(self):
        return len(self.program_info)

    def setCommentForLine(self, line_contents, index, comment):
        result = self.search(line_contents, key='exe', index=index)
        if result is None:
            print "Line wasn't found!"
            return None
        ind, inst = result
        if not isinstance(inst, CommonInstFormat):
            return None
        inst.comment = comment

        self.serializeRange(ind, ind+1, key='exe')

        return True

    # def setCommentForLine(self, line_contents, comment):
    #     result = self.search(line_contents, key="exe")
    #     if not result:
    #         return False
    #     _, instruction = result
    #     if isinstance(instruction, CommonInstFormat):
    #         instruction.comment = comment

    #         # TODO: Replace this with something better in AddressRangeManager. Very Kludgy
    #         approx_location = 0
    #         for s in self.executable_sections:
    #             start = s.instructions[0].address
    #             end = s.instructions[-1].address
    #             if start <= instruction.address  <= end:
    #                 # instruction is in this section
    #                 start, end = self.getRenderingBounds(s, instruction.address)
    #                 s.serialize(start_index=start, end_index=end)
    #                 return True
    #     return False
                    

    # def getRenderingBounds(self, section, address, size=40):
    #     s = section
    #     approx_location = int((address-start)/(end-start))
    #     half = size / 2
    #     done = False
    #     while not done:
    #         if s.instructions[approx_location-half].address <= address and s.instructions[approx_location-half].address >= address:
    #             # Found our window to render
    #             done = True
    #         elif s.instructions[approx_location-half].address > address:
    #             # Need to go down more
    #             approx_location -= size
    #         elif s.instruction[approx_location+half].address < address:
    #             # Need to go up more
    #             approx_location += size

    #     start = approx_location - half if approx_location - half >= 0 else 0
    #     end = approx_location + half if approx_location + half <= len(s.instructions) else len(s.instructions)
    #     return start, end


    def renameLabel(self, line_contents, new_name):
        m = re.search(r'0x([a-fA-F0-9]+)', line_contents)
        label_changed = False
        if m:
            addr = int(m.group(0),16)
            for sec in self.executable_sections + self.data_sections:
                if addr in sec.labels:
                    label = sec.labels[addr]
                    label.name = new_name
                    label.item.name = new_name
                    label_changed = True
                    self.renderSection(sec)
                    break
            
        return label_changed