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

    def get(self, arg1, arg2=None, arg3=1, key=None):
        if arg2 is None:
            arg2 = arg1
            arg1 = 0
        data_range = xrange(arg1, arg2)
        if key == 'exe':
            data = self._get(data_range, self.executable_sections)
        elif key == 'data':
            data = self._get(data_range, self.data_sections)
        else:
            data = ''
        return data if arg3 == 1 else reversed(data)

    def _get(self, data_range, section_array):
        data = []
        index = 0
        started = False
        for line in self.program_info:
            if index in data_range:
                data.append(data)
            index += 1
        for section in section_array:
            for line in section.string_rep:
                if index in data_range:
                    data.append(section.string_rep[index])
                index += 1
        return data

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
                index, obj = result
                index += offset
                return (index, obj)
            offset += len(section.string_rep)
        return None

    def length(self, key=None):
        if key == 'exe':
            return len(self.program_info) + sum(len(section.string_rep) for section in self.executable_sections)
        elif key == 'data':
            return len(self.program_info) + sum(len(section.string_rep) for section in self.data_sections)
        else: 
            return 0

    def getLabelIndex(self, name, key=None):
        if key == 'exe':
            return self._getLabelIndex(name, self.executable_sections)
        elif key == 'data':
            return self._getLabelIndex(name, self.data_sections)
        return None

    def _getLabelIndex(self, name, sections):
        offset = len(self.program_info)
        for section in sections:
            result = section.getLabelIndex(name)
            if result:
                return result + offset
            offset += len(section.string_rep)
        return None

    def render(self):
        for section in self.executable_sections:
            section.serialize()
        for section in self.data_sections:
            section.serialize()

    def setCommentForLine(self, line_contents, comment):
        result = self.search(line_contents, key="exe")
        if not result:
            return False
        _, instruction = result
        if isinstance(instruction, CommonInstFormat):
            instruction.comment = comment
            self.render()
            return True
        return False

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
                    self.render()
                    break
            
        return label_changed
