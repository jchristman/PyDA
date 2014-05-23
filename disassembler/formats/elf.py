from capstone import *
from disassembler.formats.common.program import CommonProgramDisassemblyFormat
from disassembler.formats.common.section import CommonSectionFormat
from disassembler.formats.common.inst import CommonInstFormat
from disassembler.formats.helpers.exceptions import BadMagicHeaderException
from disassembler.formats.helpers.flags import Flags
from ctypes import *
from struct import unpack
import sys

def disassemble(binary, filename=None):
    return ELF(binary, filename=filename)

FILETYPE_NAME = 'ELF'

# The parsing logic below is blatantly ripped off of ROPGadget v5.0:
# PE class =========================================================================================

class ELFFlags:
    ELFCLASS32  = 0x01
    ELFCLASS64  = 0x02
    EI_CLASS    = 0x04
    EI_DATA     = 0x05
    ELFDATA2LSB = 0x01
    ELFDATA2MSB = 0x02
    EM_386      = 0x03
    EM_X86_64   = 0x3e
    EM_ARM      = 0x28
    EM_MIPS     = 0x08
    EM_SPARCv8p = 0x12
    EM_PowerPC  = 0x14
    EM_ARM64    = 0xb7

class Elf32_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_uint),
                    ("e_phoff",         c_uint),
                    ("e_shoff",         c_uint),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]
 
class Elf64_Ehdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_ulonglong),
                    ("e_phoff",         c_ulonglong),
                    ("e_shoff",         c_ulonglong),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]

class Elf32_Phdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_offset",        c_uint),
                    ("p_vaddr",         c_uint),
                    ("p_paddr",         c_uint),
                    ("p_filesz",        c_uint),
                    ("p_memsz",         c_uint),
                    ("p_flags",         c_uint),
                    ("p_align",         c_uint)
                ]

class Elf64_Phdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_flags",         c_uint),
                    ("p_offset",        c_ulonglong),
                    ("p_vaddr",         c_ulonglong),
                    ("p_paddr",         c_ulonglong),
                    ("p_filesz",        c_ulonglong),
                    ("p_memsz",         c_ulonglong),
                    ("p_align",         c_ulonglong)
                ]

class Elf32_Shdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_uint),
                    ("sh_addr",         c_uint),
                    ("sh_offset",       c_uint),
                    ("sh_size",         c_uint),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_uint),
                    ("sh_entsize",      c_uint)
                ]

class Elf64_Shdr_LSB(LittleEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_ulonglong),
                    ("sh_addr",         c_ulonglong),
                    ("sh_offset",       c_ulonglong),
                    ("sh_size",         c_ulonglong),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_ulonglong),
                    ("sh_entsize",      c_ulonglong)
                ]

class Elf32_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_uint),
                    ("e_phoff",         c_uint),
                    ("e_shoff",         c_uint),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]
 
class Elf64_Ehdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_ulonglong),
                    ("e_phoff",         c_ulonglong),
                    ("e_shoff",         c_ulonglong),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort)
                ]

class Elf32_Phdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_offset",        c_uint),
                    ("p_vaddr",         c_uint),
                    ("p_paddr",         c_uint),
                    ("p_filesz",        c_uint),
                    ("p_memsz",         c_uint),
                    ("p_flags",         c_uint),
                    ("p_align",         c_uint)
                ]

class Elf64_Phdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_flags",         c_uint),
                    ("p_offset",        c_ulonglong),
                    ("p_vaddr",         c_ulonglong),
                    ("p_paddr",         c_ulonglong),
                    ("p_filesz",        c_ulonglong),
                    ("p_memsz",         c_ulonglong),
                    ("p_align",         c_ulonglong)
                ]

class Elf32_Shdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_uint),
                    ("sh_addr",         c_uint),
                    ("sh_offset",       c_uint),
                    ("sh_size",         c_uint),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_uint),
                    ("sh_entsize",      c_uint)
                ]

class Elf64_Shdr_MSB(BigEndianStructure):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_ulonglong),
                    ("sh_addr",         c_ulonglong),
                    ("sh_offset",       c_ulonglong),
                    ("sh_size",         c_ulonglong),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_ulonglong),
                    ("sh_entsize",      c_ulonglong)
                ]

""" This class parses the ELF """
class ELF:
    FILETYPE_NAME = 'ELF'
    def __init__(self, binary, filename=None):
        self.__binary    = bytearray(binary)
        self.__filename = filename

        self.__ElfHeader = None
        self.__shdr_l    = []
        self.__phdr_l    = []

        self.__setHeaderElf()
        self.__setShdr()
        self.__setPhdr()
    
    def disassemble(self, settings_manager):
        md = capstone.Cs(self.getArch(), self.getArchMode())
        disassembly = CommonProgramDisassemblyFormat(self.getProgramInfo(), settings_manager)

        for s in self.getExecSections():
            #s["name"] = s["name"].replace('\x00','')
            section = CommonSectionFormat(disassembly, s["name"], self.getArch(), self.getArchMode(), s["vaddr"], Flags("rwx")) #TODO: make flags more accurate

            # linear sweep (for now)
            for inst in md.disasm(s["opcodes"], s["vaddr"]):
                section.addInst(CommonInstFormat(inst.address, inst.mnemonic, inst.op_str, inst.bytes))
            
            section.searchForStrings()
            section.searchForFunctions()
            section.addStringLabels()
            section.addFunctionLabels()
            disassembly.addSection(section.sort())

        for s in self.getDataSections():
            s["name"] = s["name"].replace('\x00','')
            section = CommonSectionFormat(disassembly, s["name"], self.getArch(), self.getArchMode(), s["vaddr"], Flags("r--"), bytes=s["opcodes"]) #TODO: make flags more accurate
            section.searchForStrings()
            # section.searchForFunctions()
            section.addStringLabels()
            # section.addFunctionLabels()
            disassembly.addSection(section.sort())

        return disassembly


    """ Parse ELF header """
    def __setHeaderElf(self):
        e_ident = str(self.__binary[:15])

        ei_class = unpack("<B", e_ident[ELFFlags.EI_CLASS])[0]
        ei_data  = unpack("<B", e_ident[ELFFlags.EI_DATA])[0]

        if ei_class != ELFFlags.ELFCLASS32 and ei_class != ELFFlags.ELFCLASS64:
            print "[Error] ELF.__setHeaderElf() - Bad Arch size"
            return None

        if ei_data != ELFFlags.ELFDATA2LSB and ei_data != ELFFlags.ELFDATA2MSB:
            print "[Error] ELF.__setHeaderElf() - Bad architecture endian"
            return None

        if ei_class == ELFFlags.ELFCLASS32: 
            if   ei_data == ELFFlags.ELFDATA2LSB:
                self.__ElfHeader = Elf32_Ehdr_LSB.from_buffer_copy(self.__binary)
            elif ei_data == ELFFlags.ELFDATA2MSB:
                self.__ElfHeader = Elf32_Ehdr_MSB.from_buffer_copy(self.__binary)
        elif ei_class == ELFFlags.ELFCLASS64: 
            if   ei_data == ELFFlags.ELFDATA2LSB:
                self.__ElfHeader = Elf64_Ehdr_LSB.from_buffer_copy(self.__binary)
            elif ei_data == ELFFlags.ELFDATA2MSB:
                self.__ElfHeader = Elf64_Ehdr_MSB.from_buffer_copy(self.__binary)

        #print 'header: ',self.__ElfHeader.e_machine
        #print 'flags: ',self.__ElfHeader.e_flags

        self.getArch() # Check if architecture is supported

    """ Parse Section header """
    def __setShdr(self):
        shdr_num = self.__ElfHeader.e_shnum
        base = self.__binary[self.__ElfHeader.e_shoff:]
        shdr_l = []

        e_ident = str(self.__binary[:15])
        ei_data = unpack("<B", e_ident[ELFFlags.EI_DATA])[0]

        for i in range(shdr_num):

            if self.getArchMode() & CS_MODE_32 == CS_MODE_32:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf32_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf32_Shdr_MSB.from_buffer_copy(base)
                else: raise Exception()
            elif self.getArchMode() & CS_MODE_64 == CS_MODE_64:
                if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf64_Shdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf64_Shdr_MSB.from_buffer_copy(base)
                else: raise Exception()
            elif self.getArchMode() & CS_MODE_ARM == CS_MODE_ARM:
                if self.__ElfHeader.e_machine == ELFFlags.EM_ARM:
                    if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf32_Shdr_LSB.from_buffer_copy(base)
                    elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf32_Shdr_MSB.from_buffer_copy(base)
                elif self.__ElfHeader.e_machine == ELFFlags.EM_ARM64:
                    if   ei_data == ELFFlags.ELFDATA2LSB: shdr = Elf64_Shdr_LSB.from_buffer_copy(base)
                    elif ei_data == ELFFlags.ELFDATA2MSB: shdr = Elf64_Shdr_MSB.from_buffer_copy(base)
            else:
                raise Exception("Not arm, not x64, not x86.\n")

            self.__shdr_l.append(shdr)
            base = base[self.__ElfHeader.e_shentsize:]

        # setup name from the strings table
        string_table = str(self.__binary[(self.__shdr_l[self.__ElfHeader.e_shstrndx].sh_offset):])
        for i in range(shdr_num):
            self.__shdr_l[i].str_name = string_table[self.__shdr_l[i].sh_name:].split('\0')[0]

    """ Parse Program header """
    def __setPhdr(self):
        pdhr_num = self.__ElfHeader.e_phnum
        base = self.__binary[self.__ElfHeader.e_phoff:]
        phdr_l = []

        e_ident = str(self.__binary[:15])
        ei_data = unpack("<B", e_ident[ELFFlags.EI_DATA])[0]

        for i in range(pdhr_num):
            if self.getArchMode() & CS_MODE_32 == CS_MODE_32:
                if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf32_Phdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf32_Phdr_MSB.from_buffer_copy(base)
                else: raise Exception()
            elif self.getArchMode() & CS_MODE_64 == CS_MODE_64:
                if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf64_Phdr_LSB.from_buffer_copy(base)
                elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf64_Phdr_MSB.from_buffer_copy(base)
                else: raise Exception()
            elif self.getArchMode() & CS_MODE_ARM == CS_MODE_ARM:
                if self.__ElfHeader.e_machine == ELFFlags.EM_ARM:
                    if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf32_Phdr_LSB.from_buffer_copy(base)
                    elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf32_Phdr_MSB.from_buffer_copy(base)
                    else: raise Exception()
                elif self.__ElfHeader.e_machine == ELFFlags.EM_ARM64:
                    if   ei_data == ELFFlags.ELFDATA2LSB: phdr = Elf64_Shdr_LSB.from_buffer_copy(base)
                    elif ei_data == ELFFlags.ELFDATA2MSB: phdr = Elf64_Shdr_MSB.from_buffer_copy(base)
                    else: raise Exception()
            else:
                raise Exception("Not arm, not x64, not x86.\n")

            self.__phdr_l.append(phdr)
            base = base[self.__ElfHeader.e_phentsize:]

    def getEntryPoint(self):
        return self.__ElfHeader.e_entry

    def getExecSections(self):
        #ret = []
        #for segment in self.__phdr_l:
        #    if segment.p_flags & 0x1:
        #        ret +=  [{
        #                    "name"    : "",
        #                    "offset"  : segment.p_offset,
        #                    "size"    : segment.p_memsz,
        #                    "vaddr"   : segment.p_vaddr,
        #                    "opcodes" : str(self.__binary[segment.p_offset:segment.p_offset+segment.p_memsz])
        #                }]

        ret = []
        for section in self.__shdr_l:
            if section.sh_flags & 0x4:
                #if section.str_name == '.text':
                    #print hex(section.sh_type),'type'
                    #print hex(section.sh_flags),'flags'
                    #print hex(section.sh_addr),'addr'
                    #print hex(section.sh_offset),'offset'
                    #print hex(section.sh_size),'size'
                    #print hex(section.sh_link),'link'
                    #print hex(section.sh_info),'info'
                    #print hex(section.sh_addralign),'addralign'
                    #print hex(section.sh_entsize),'entsize'
                    #print repr(str(self.__binary[section.sh_offset:section.sh_offset+section.sh_size]).encode('hex'))

                ret +=  [{
                            "name"    : section.str_name,
                            "offset"  : section.sh_offset,
                            "size"    : section.sh_size,
                            "vaddr"   : section.sh_addr,
                            "opcodes" : str(self.__binary[section.sh_offset:section.sh_offset+section.sh_size])
                        }]

        return ret

    def getDataSections(self):
        ret = []
        for section in self.__shdr_l:
            if not (section.sh_flags & 0x4) and (section.sh_flags & 0x2):
                ret +=  [{
                            "name"    : section.str_name,
                            "offset"  : section.sh_offset,
                            "size"    : section.sh_size,
                            "vaddr"   : section.sh_addr,
                            "opcodes" : str(self.__binary[section.sh_offset:section.sh_offset+section.sh_size])
                        }]
        return ret

    def getArch(self):
        if self.__ElfHeader.e_machine == ELFFlags.EM_386 or self.__ElfHeader.e_machine == ELFFlags.EM_X86_64: 
            return CS_ARCH_X86
        elif self.__ElfHeader.e_machine == ELFFlags.EM_ARM:
            return CS_ARCH_ARM
        elif self.__ElfHeader.e_machine == ELFFlags.EM_ARM64:
            return CS_ARCH_ARM64
        elif self.__ElfHeader.e_machine == ELFFlags.EM_MIPS:
            return CS_ARCH_MIPS
        elif self.__ElfHeader.e_machine == ELFFlags.EM_PowerPC:
            return CS_ARCH_PPC
        elif self.__ElfHeader.e_machine == ELFFlags.EM_SPARCv8p:
            return CS_ARCH_SPARC
        else:
            print "[Error] ELF.getArch() - Architecture not supported"
            sys.stderr.write("[Error] ELF.getArch() - Architecture not supported")
            return None
            
    def getArchMode(self):
        if self.__ElfHeader.e_machine == ELFFlags.EM_ARM or self.__ElfHeader.e_machine == ELFFlags.EM_ARM64:
            mode = CS_MODE_ARM
            e_ident = str(self.__binary[:15])
            ei_data = unpack("<B", e_ident[ELFFlags.EI_DATA])[0]
            if   ei_data == ELFFlags.ELFDATA2LSB:
                #print "LITTLE_ENDIAN"
                mode = CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN + CS_MODE_THUMB
            elif ei_data == ELFFlags.ELFDATA2MSB:
                #print "BIG_ENDIAN"
                mode = CS_MODE_ARM + CS_MODE_BIG_ENDIAN + CS_MODE_THUMB
            return mode
        elif self.__ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS32: 
            return CS_MODE_32
        elif self.__ElfHeader.e_ident[ELFFlags.EI_CLASS] == ELFFlags.ELFCLASS64: 
            return CS_MODE_64
        else:
            print "[Error] ELF.getArchMode() - Bad Arch size"
            sys.stderr.write("[Error] ELF.getArchMode() - Bad Arch size")
            return None

    def getFormat(self):
        return "ELF"
    
    def getProgramInfo(self):
        import hashlib
        fields = {
            "File MD5": hashlib.md5(self.__binary).hexdigest(),
            "File Format": self.FILETYPE_NAME,
            "Architecture": "x86" if self.getArch() == CS_ARCH_X86 else "ARM",
            "Architecture Mode": "32-bit" if self.getArchMode() == CS_MODE_32 else "64-bit",
            "Entry Point": "0x{:x}".format(self.getEntryPoint()),
        }
        if self.__filename != None:
            fields["Filename"] = self.__filename
        
        max_length = max(len(x) + len(fields[x]) for x in fields) + 2

        program_info = "#"*(max_length+12) + "\n"
        for x in fields:
            program_info += "###" 
            program_info += ("   {:<%d}   " % max_length).format(x + ": " + fields[x])
            program_info += "###\n"
        program_info += "#"*(max_length+12) + "\n"

        return program_info
