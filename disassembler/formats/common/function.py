import struct
from disassembler.formats.helpers.label import Label
from disassembler.formats.helpers.models import DataModel

class CommonFunctionFormat:
    def __init__(self, start_inst_index, end_inst_index, name, parent_section):
        self.name = name
        self.parent_section = parent_section
        self.start_address = self.parent_section.instructions[start_inst_index].address
        self.end_address = self.parent_section.instructions[end_inst_index].address
        self.function_instructions = self.parent_section.instructions[start_inst_index : end_inst_index + 1]
        for inst in self.function_instructions:
            inst.function = self

    @staticmethod
    def length(function):
        return 1

    @staticmethod
    def toString(function):
        pass
