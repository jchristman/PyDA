import struct
from disassembler.formats.helpers.label import Label
from disassembler.formats.helpers.models import AbstractDataModel
from disassembler.formats.common.section import CommonSectionFormat, CommonExecutableSectionFormat, CommonDataSectionFormat

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

    def search(self, string, key=None):
        if key == 'exe':
            return self._search(string, self.executable_sections)
        elif key == 'data':
            return self._search(string, self.data_sections)
        return None

    def _search(self, string, sections):
        offset = len(self.program_info)
        for section in sections:
            result = section.search(string)
            if result:
                return result
            offset += len(section.string_rep)
        return None

    def length(self, key=None):
        if key == 'exe':
            return len(self.program_info) + sum(len(section.string_rep) for section in self.executable_sections)
        elif key == 'data':
            return len(self.program_info) + sum(len(section.string_rep) for section in self.data_sections)
        else: 
            return 0
