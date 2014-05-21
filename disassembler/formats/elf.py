import capstone
from disassembler.formats.common.program import CommonProgramDisassemblyFormat
from disassembler.formats.common.section import CommonSectionFormat
from disassembler.formats.common.inst import CommonInstFormat
from disassembler.formats.helpers.exceptions import BadMagicHeaderException
from disassembler.formats.helpers.flags import Flags
from struct import unpack

BYTE = 1    # 8 bits
HWORD = 2   # 16 bits
WORD = 4    # 32 bits
DWORD = 8   # 64 bits

def disassemble(binary, filename=None):
    return ELF(binary, filename=filename)
#except: return False

FILETYPE_NAME = 'ELF'

class ELF:
    FILETYPE_NAME = 'ELF'
    def __init__(self, binary, filename=None):
        magic_offset = 0
        if not binary[magic_offset : magic_offset + WORD] == '\x7FELF':
            raise BadMagicHeaderException()
        
        self.binary = binary
        self.filename = filename

        offset = 4
        self.bin_class = capstone.CS_MODE_32 if unpack('B', self.binary[offset : offset + BYTE])[0] == 1 else capstone.CS_MODE_64
        self.word = ('Q' if self.bin_class == capstone.CS_MODE_64 else 'I', DWORD if self.bin_class == capstone.CS_MODE_64 else WORD)
        offset = 5
        self.endian = capstone.CS_MODE_LITTLE_ENDIAN if unpack('B', self.binary[offset : offset + BYTE])[0] == 1 else capstone.CS_MODE_BIG_ENDIAN
        self.end = '<' if self.endian == capstone.CS_MODE_LITTLE_ENDIAN else '>'
        offset = 7
        os_values = {
                0x00 : 'System V',
                0x01 : 'HP-UX',
                0x02 : 'NetBSD',
                0x03 : 'Linux',
                0x06 : 'Solaris',
                0x07 : 'AIX',
                0x08 : 'IRIX',
                0x09 : 'FreeBSD',
                0x0C : 'OpenBSD'
                }
        self.os = os_values[unpack('B', self.binary[offset : offset + BYTE])[0]]
        offset = 0x10
        type_values     =   {
                1 : 'relocatable',
                2 : 'executable',
                3 : 'shared',
                4 : 'core'
                }
        self.type = type_values[unpack(self.end + 'H', self.binary[offset : offset + HWORD])[0]]
        offset = 0x12
        arch_values     =   {
                #                0x02 : capstone.CS_ARCH_SPARC, Next version will have sparc
                0x03 : capstone.CS_ARCH_X86,
                0x08 : capstone.CS_ARCH_MIPS,
                0x14 : capstone.CS_ARCH_PPC,
                0x28 : capstone.CS_ARCH_ARM,
                0x32 : False, # IA_64 not yet supported in capstone
                0x3E : capstone.CS_ARCH_X86, # This is actually x86_64 which I think is taken care of by the CS_MODE_64
                0xB7 : capstone.CS_ARCH_ARM64
                }
        self.arch = arch_values[unpack(self.end + 'H', self.binary[offset : offset + HWORD])[0]]
        offset = 0x18
        self.entry_point = unpack(self.end + self.word[0], self.binary[offset : offset + self.word[1]])[0]
        offset += self.word[1]
        self.program_header_offset = unpack(self.end + self.word[0], self.binary[offset : offset + self.word[1]])[0]
        offset += self.word[1]
        self.section_header_offset = unpack(self.end + self.word[0], self.binary[offset : offset + self.word[1]])[0]
        offset += self.word[1]
        self.flags = unpack(self.end + 'I', self.binary[offset : offset + WORD])[0]
        offset += WORD
        self.header_size = unpack(self.end + 'H', self.binary[offset : offset + HWORD])[0]
        offset += HWORD
        self.program_header_entry_size = unpack(self.end + 'H', self.binary[offset : offset + HWORD])[0]
        offset += HWORD
        self.program_header_entry_num = unpack(self.end + 'H', self.binary[offset : offset + HWORD])[0]
        offset += HWORD
        self.section_header_entry_size = unpack(self.end + 'H', self.binary[offset : offset + HWORD])[0]
        offset += HWORD
        self.section_header_entry_num = unpack(self.end + 'H', self.binary[offset : offset + HWORD])[0]
        offset += HWORD
        self.section_header_str_index = unpack(self.end + 'H', self.binary[offset : offset + HWORD])[0]

        self.parseSections()

    def parseSections(self):
        self.sections = []
        section_names = Section(self, self.section_header_str_index, self.section_header_entry_size, self.word)
        section_names_strings = self.binary[section_names.sh_offset : section_names.sh_offset + section_names.sh_size]
        
        for i in xrange(self.section_header_entry_num):
            section = Section(self, i, self.section_header_entry_size, self.word)
            section.sh_name_string = section_names_strings[section.sh_name:].split('\x00')[0]
            self.sections.append(section)

        self.sections.sort(key=lambda i: i.sh_offset)

    def disassemble(self, settings_manager):
        md = capstone.Cs(self.arch, self.bin_class)
            
        disassembly = CommonProgramDisassemblyFormat(self.getProgramInfo(), settings_manager)
        for s in self.sections:
            section = None
            sCODE = self.binary[s.sh_offset : s.sh_offset + s.sh_size]
            if len(s.sh_name_string) == 0:
                continue
            elif s.sh_name_string in ELF.dont_disassemble:
                section = CommonSectionFormat(disassembly, s.sh_name_string, self.arch, self.bin_class, s.sh_addr, Flags("r--"), bytes=sCODE) #TODO: make flags more accurate
            else:
                section = CommonSectionFormat(disassembly, s.sh_name_string, self.arch, self.bin_class, s.sh_addr, Flags("rwx")) #TODO: make flags more accurate
                
                # linear sweep (for now)
                for inst in md.disasm(sCODE, s.sh_addr):
                    section.addInst(CommonInstFormat(inst.address, inst.mnemonic, inst.op_str, inst.bytes))

            section.searchForStrings()
            section.searchForFunctions()
            section.addStringLabels()
            section.addFunctionLabels()

            disassembly.addSection(section.sort())
        return disassembly

    def getArchName(self):
        arc = None
        if self.arch == capstone.CS_ARCH_X86:
            arc = "x86"
        elif self.arch == capstone.CS_ARCH_PPC:
            arc = "PPC"
        elif self.arch == capstone.CS_ARCH_ARM:
            arc = "ARM"
        elif self.arch == capstone.CS_ARCH_ARM64:
            arc = "ARM64"

        return arc

    def getProgramInfo(self):
        import hashlib
        fields = {
            "File MD5": hashlib.md5(self.binary).hexdigest(),
            "File Format": self.FILETYPE_NAME,
            "Architecture": self.getArchName(),
            "Architecture Mode": "32-bit" if self.bin_class == capstone.CS_MODE_32 else "64-bit",
            "Entry Point": "0x{:x}".format(self.entry_point),
        }

        if self.filename != None:
            fields["Filename"] = self.filename
        
        max_length = max(len(x) + len(fields[x]) for x in fields) + 2

        program_info = "#"*(max_length+12) + "\n"
        for x in fields:
            program_info += "###" 
            program_info += ("   {:<%d}   " % max_length).format(x + ": " + fields[x])
            program_info += "###\n"
        program_info += "#"*(max_length+12) + "\n"

        return program_info

    dont_disassemble = ['.comment','.shstrtab','.symtab','.strtab','.note.ABI-tag','.note.gnu.build-id','.hash','.gnu.hash','.dynsym','.dynstr','.gnu.version','.gnu.version_r','.rodata','.eh_frame','.init_array','.jcr','.dynamic','.got','.got.plt','.data','.bss','.interp','.eh_frame_hdr','.plt','.init','.rel.plt','.rel.dyn','.rela.plt','.rela.dyn']

class Section:
    def __init__(self, elf, index, entry_size, word):
        entry_offset = elf.section_header_offset + index * entry_size
        self.sh_name      = unpack(elf.end + 'I', elf.binary[entry_offset : entry_offset + 4])[0] # Always 4 bytes
        self.sh_type      = unpack(elf.end + 'I', elf.binary[entry_offset + 4 : entry_offset + 8])[0] # Always 4 bytes
        self.sh_flags     = unpack(elf.end + word[0], elf.binary[entry_offset + 8 : entry_offset + 8 + word[1]])[0] # 32 or 64 bits
        self.sh_addr      = unpack(elf.end + word[0], elf.binary[entry_offset + 8 + word[1] : entry_offset + 8 + word[1] * 2])[0] # 32 or 64 bits
        self.sh_offset    = unpack(elf.end + word[0], elf.binary[entry_offset + 8 + word[1] * 2: entry_offset + 8 + word[1] * 3])[0] # 32 or 64 bits
        self.sh_size      = unpack(elf.end + word[0], elf.binary[entry_offset + 8 + word[1] * 3 : entry_offset + 8 + word[1] * 4])[0] # 32 or 64 bits
        self.sh_link      = unpack(elf.end + 'I', elf.binary[entry_offset + 8 + word[1] * 4 : entry_offset + 12 + word[1] * 4])[0] # Always 4 bytes
        self.sh_info      = unpack(elf.end + 'I', elf.binary[entry_offset + 12 + word[1] * 4 : entry_offset + 16 + word[1] * 4])[0] # Always 4 bytes
        self.sh_addralign = unpack(elf.end + word[0], elf.binary[entry_offset + 16 + word[1] * 4 : entry_offset + 16 + word[1] * 5])[0] # 32 or 64 bits
        self.sh_entrsize  = unpack(elf.end + word[0], elf.binary[entry_offset + 16 + word[1] * 5 : entry_offset + 16 + word[1] * 6])[0] # 32 or 64 bits

