import capstone
from helpers import *
from struct import unpack

def disassemble(binary):
    return ELF(binary)
#    except: return False

#### REQUIRED FUNCTIONS ####
#    ### Parse the Program Header ###
#    segments = []
#    entry_size = options['program_header_entry_size']
#    word_size = 4 if options['class'] == capstone.CS_MODE_32 else 8
#    for i in xrange(options['program_header_entry_num']):
#        entry_offset = options['program_header_offset'] + i * entry_size
#        segment = {}
#        segment['p_type']   = unpack('AAAA', binary[entry_offset + word_size * 0 : entry_offset + word_size * 1])[0]
#        segment['p_offset'] = unpack('AAAA', binary[entry_offset + word_size * 1 : entry_offset + word_size * 2])[0]
#        segment['p_vaddr']  = unpack('AAAA', binary[entry_offset + word_size * 2 : entry_offset + word_size * 3])[0]
#        segment['p_paddr']  = unpack('AAAA', binary[entry_offset + word_size * 3 : entry_offset + word_size * 4])[0]
#        segment['p_filesz'] = unpack('AAAA', binary[entry_offset + word_size * 4 : entry_offset + word_size * 5])[0]
#        segment['p_memsz']  = unpack('AAAA', binary[entry_offset + word_size * 5 : entry_offset + word_size * 6])[0]
#        segment['p_flags']  = unpack('AAAA', binary[entry_offset + word_size * 6 : entry_offset + word_size * 7])[0]
#        segment['p_align']  = unpack('AAAA', binary[entry_offset + word_size * 7 : entry_offset + word_size * 8])[0]
#        segments.append(segment)

#### END REQUIRED FUNCTIONS ####
class ELF:
    def __init__(self, binary):
        magic_offset = 0
        if not binary[magic_offset : magic_offset + WORD] == '\x7FELF':
            raise BadMagicHeaderException()

        self.binary = binary

        ### PARSE THE ELF HEADER NOW ###
        offset = 4
        self.bin_class = capstone.CS_MODE_32 if unpack('B', binary[offset : offset + BYTE])[0] == 1 else capstone.CS_MODE_64
        self.word = ('Q' if self.bin_class == capstone.CS_MODE_64 else 'I', DWORD if self.bin_class == capstone.CS_MODE_64 else WORD)
        offset = 5
        self.endian = capstone.CS_MODE_LITTLE_ENDIAN if unpack('B', binary[offset : offset + BYTE])[0] == 1 else capstone.CS_MODE_BIG_ENDIAN
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
        self.os = os_values[unpack('B', binary[offset : offset + BYTE])[0]]
        offset = 0x10
        type_values     =   {
                1 : 'relocatable',
                2 : 'executable',
                3 : 'shared',
                4 : 'core'
                }
        self.type = type_values[unpack(self.end + 'H', binary[offset : offset + HWORD])[0]]
        offset = 0x12
        arch_values     =   {
                0x02 : False, # SPARC not yet supported in capstone
                0x03 : capstone.CS_ARCH_X86,
                0x08 : capstone.CS_ARCH_MIPS,
                0x14 : capstone.CS_ARCH_PPC,
                0x28 : capstone.CS_ARCH_ARM,
                0x32 : False, # IA_64 not yet supported in capstone
                0x3E : capstone.CS_ARCH_X86, # This is actually x86_64 which I think is taken care of by the CS_MODE_64
                0xB7 : capstone.CS_ARCH_ARM64
                }
        self.arch = arch_values[unpack(self.end + 'H', binary[offset : offset + HWORD])[0]]
        offset = 0x18
        self.entry_point = unpack(self.end + self.word[0], binary[offset : offset + self.word[1]])[0]
        offset += self.word[1]
        self.program_header_offset = unpack(self.end + self.word[0], binary[offset : offset + self.word[1]])[0]
        offset += self.word[1]
        self.section_header_offset = unpack(self.end + self.word[0], binary[offset : offset + self.word[1]])[0]
        offset += self.word[1]
        self.flags = unpack(self.end + 'I', binary[offset : offset + WORD])[0]
        offset += WORD
        self.header_size = unpack(self.end + 'H', binary[offset : offset + HWORD])[0]
        offset += HWORD
        self.program_header_entry_size = unpack(self.end + 'H', binary[offset : offset + HWORD])[0]
        offset += HWORD
        self.program_header_entry_num = unpack(self.end + 'H', binary[offset : offset + HWORD])[0]
        offset += HWORD
        self.section_header_entry_size = unpack(self.end + 'H', binary[offset : offset + HWORD])[0]
        offset += HWORD
        self.section_header_entry_num = unpack(self.end + 'H', binary[offset : offset + HWORD])[0]
        offset += HWORD
        self.section_header_str_index = unpack(self.end + 'H', binary[offset : offset + HWORD])[0]

        self.parseSections()

    def parseSections(self):
        self.sections = []
        section_names = ELF.Section(self, self.section_header_str_index, self.section_header_entry_size, self.word[1])
        section_names_strings = self.binary[section_names.sh_offset : section_names.sh_offset + section_names.sh_size]
        
        for i in xrange(self.section_header_entry_num):
            section = ELF.Section(self, i, self.section_header_entry_size, self.word[1])
            section.sh_name_string = section_names_strings[section.sh_name:].split('\x00')[0]
            self.sections.append(section)

        self.sections.sort(key=lambda i: i.sh_offset)
        return self.sections

    class Section:
        def __init__(self, elf, index, entry_size, word_size):
            entry_offset = elf.section_header_offset + index * entry_size
            self.sh_name      = unpack(elf.end + 'I', elf.binary[entry_offset : entry_offset + 4])[0] # Always 4 bytes
            self.sh_type      = unpack(elf.end + 'I', elf.binary[entry_offset + 4 : entry_offset + 8])[0] # Always 4 bytes
            self.sh_flags     = unpack(elf.end + 'I', elf.binary[entry_offset + 8 : entry_offset + 8 + word_size])[0] # 32 or 64 bits
            self.sh_addr      = unpack(elf.end + 'I', elf.binary[entry_offset + 8 + word_size : entry_offset + 8 + word_size * 2])[0] # 32 or 64 bits
            self.sh_offset    = unpack(elf.end + 'I', elf.binary[entry_offset + 8 + word_size * 2: entry_offset + 8 + word_size * 3])[0] # 32 or 64 bits
            self.sh_size      = unpack(elf.end + 'I', elf.binary[entry_offset + 8 + word_size * 3 : entry_offset + 8 + word_size * 4])[0] # 32 or 64 bits
            self.sh_link      = unpack(elf.end + 'I', elf.binary[entry_offset + 8 + word_size * 4 : entry_offset + 12 + word_size * 4])[0] # Always 4 bytes
            self.sh_info      = unpack(elf.end + 'I', elf.binary[entry_offset + 12 + word_size * 4 : entry_offset + 16 + word_size * 4])[0] # Always 4 bytes
            self.sh_addralign = unpack(elf.end + 'I', elf.binary[entry_offset + 16 + word_size * 4 : entry_offset + 16 + word_size * 5])[0] # 32 or 64 bits
            self.sh_entrsize  = unpack(elf.end + 'I', elf.binary[entry_offset + 16 + word_size * 5 : entry_offset + 16 + word_size * 6])[0] # 32 or 64 bits
