from concurrent.futures import AbstractProcessObject, UnknownProcessCommandException
from disassembler.formats.helpers.models import AbstractDataModel
from settings import *
import sys
# import traceback

class Disassembler(AbstractProcessObject, AbstractDataModel):
    def __init__(self, settings_manager, multiprocessing_proxy=None):
        self.settings_manager = settings_manager
        self.dis_object = None

    def load(self, binary, filename = None):
        self.binary = binary
        for format in IMPORTED_FORMATS:
            try:
                self.dis = format.disassemble(self.binary, filename=filename)
                break
            except:
                print 'File header did not match %s' % format.FILETYPE_NAME
                # traceback.print_exc()
        if not self.dis:
            raise UnsupportedBinaryFormatException()

    def getFileType(self):
        return self.dis.FILETYPE_NAME

    def disassembleFile(self, file_name):
        binary = open(file_name, 'rb').read()
        self.load(binary, filename=file_name)
        disassembly = self.disassemble()
        return disassembly

    def disassemble(self):
        return self.dis.disassemble(self.settings_manager)

    ####### ABSTRACT PROCESS OBJECT FUNCTION #######
    def execute(self, cmd_str, args):
        print cmd_str, args
        if cmd_str == 'DISASSEMBLE':    self.dis_object = self.disassembleFile(*args)
        elif cmd_str == 'GET':          return self.get(*args)
        elif cmd_str == 'GETITEM':      return self.getitem(*args)
        elif cmd_str == 'SET':          self.set(*args)
        elif cmd_str == 'APPEND':       self.append(*args)
        elif cmd_str == 'SEARCH':       return self.search(*args)
        elif cmd_str == 'LENGTH':       return self.length(*args)
        else:                           raise UnknownProcessCommandException()
        return None

    ####### ABSTRACT DATA MODEL FUNCTIONS #######
    def get(self, arg1, arg2=None, arg3=1, key=None):
        return self.dis_object.get(arg1, arg2, arg3, key):

    def getitem(self, index, key=None):
        return self.dis_object.get(index, key)

    def set(self, index, item, key=None):
        self.dis_object.set(index, item, key)

    def append(self, item, key=None):
        self.dis_object.append(index, item, key)

    def search(self, string, key=None):
        return self.dis_object.search(string, key)

    def length(self, key=None):
        return self.dis_object.length(key)

class UnsupportedBinaryFormatException(Exception):
    pass
