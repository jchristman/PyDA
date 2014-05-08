import struct
from disassembler.formats.helpers.label import Label
from disassembler.formats.helpers.models import DataModel
from disassembler.formats.common.section import CommonSectionFormat, CommonExecutableSectionFormat, CommonDataSectionFormat

class CommonProgramDisassemblyFormat:
    '''
    All the CommonProgramDisassemblyFormat will do now is have an array of Data Models
    that will be used to access and mutate the information in the data structure.
    '''
    def __init__(self, program_info, settings_manager):
        self.program_info = program_info
        self.settings_manager = settings_manager

        self.initVars()

        self.executable_sections = DataModel([], toFunc=CommonExecutableSectionFormat.toString, 
                lengthFunc=CommonExecutableSectionFormat.length)
        self.data_sections = DataModel([], toFunc=CommonDataSectionFormat.toString,
                lengthFunc=CommonDataSectionFormat.length)

        for line in self.program_info.split('\n'):
            self.executable_sections.append(line + '\n')
        self.executable_sections.append(' \n')

    def initVars(self):
        self.PYDA_SECTION = self.settings_manager.get('context','pyda-section')
        self.PYDA_ADDRESS = self.settings_manager.get('context', 'pyda-address')
        self.PYDA_MNEMONIC = self.settings_manager.get('context', 'pyda-mnemonic')
        self.PYDA_OP_STR = self.settings_manager.get('context', 'pyda-op-str')
        self.PYDA_COMMENT = self.settings_manager.get('context', 'pyda-comment')
        self.PYDA_LABEL = self.settings_manager.get('context', 'pyda-label')
        self.PYDA_BYTES = self.settings_manager.get('context', 'pyda-bytes')
        self.PYDA_GENERIC = self.settings_manager.get('context', 'pyda-generic')
        self.PYDA_ENDL = self.settings_manager.get('context', 'pyda-endl')
        self.NUM_OPCODE_BYTES_SHOWN = self.settings_manager.getint('disassembly','num-opcode-bytes-shown')
        self.MIN_STRING_SIZE = self.settings_manager.getint('disassembly','min-string-size')

    def addSection(self, section):
        if isinstance(section, CommonSectionFormat):
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
