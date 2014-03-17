import capstone

#### REQUIRED FUNCTIONS ####
def parse_program(binary):
    options = {'file_type' : 'ELF'}

    ### Parse the ELF Header ###
    options['class'] = capstone.CS_MODE_32 if getint(binary[ELF.Class.offset : ELF.Class.offset + ELF.Class.size]) == 1 else capstone.CS_MODE_64
    options['endian'] = capstone.CS_MODE_LITTLE_ENDIAN if getint(binary[ELF.Endianness.offset : ELF.Endianness.offset + ELF.Endianness.size]) == 1 else capstone.CS_MODE_BIG_ENDIAN
    options['os'] = ELF.OS.values[getint(binary[ELF.OS.offset : ELF.OS.offset + ELF.OS.size])]

    endianness = False
    if options['endian'] == capstone.CS_MODE_LITTLE_ENDIAN:
        endianness = True
        
    options['type'] = ELF.Type.values[getint(binary[ELF.Type.offset : ELF.Type.offset + ELF.Type.size], endianness)]
    options['arch'] = ELF.Arch.values[getint(binary[ELF.Arch.offset : ELF.Arch.offset + ELF.Arch.size], endianness)]
    if options['class'] == capstone.CS_MODE_32:
        options['entry_point'] = getint(binary[ELF.EntryPoint.offset : ELF.EntryPoint.offset + ELF.EntryPoint.size_32], endianness)
        options['program_header_offset'] = getint(binary[ELF.PHTable.offset_32 : ELF.PHTable.offset_32 + ELF.PHTable.size_32], endianness)
        options['section_header_offset'] = getint(binary[ELF.SHTable.offset_32 : ELF.SHTable.offset_32 + ELF.SHTable.size_32], endianness)
        options['flags'] = getint(binary[ELF.Flags.offset_32 : ELF.Flags.offset_32 + ELF.Flags.size], endianness)
        options['header_size'] = getint(binary[ELF.HeaderSize.offset_32 : ELF.HeaderSize.offset_32 + ELF.HeaderSize.size], endianness)
        options['program_header_entry_size'] = getint(binary[ELF.PHEntrySize.offset_32 : ELF.PHEntrySize.offset_32 + ELF.PHEntrySize.size], endianness)
        options['program_header_entry_num'] = getint(binary[ELF.PHNumber.offset_32 : ELF.PHNumber.offset_32 + ELF.PHNumber.size], endianness)
        options['section_header_entry_size'] = getint(binary[ELF.SHEntrySize.offset_32 : ELF.SHEntrySize.offset_32 + ELF.SHEntrySize.size], endianness)
        options['section_header_entry_num'] = getint(binary[ELF.SHNumber.offset_32 : ELF.SHNumber.offset_32 + ELF.SHNumber.size], endianness)
        options['section_header_str_index'] = getint(binary[ELF.SHStrIndex.offset_32 : ELF.SHStrIndex.offset_32 + ELF.SHStrIndex.size], endianness)
    else:
        options['entry_point'] = getint(binary[ELF.EntryPoint.offset : ELF.EntryPoint.offset + ELF.EntryPoint.size_64], endianness)
        options['program_header_offset'] = getint(binary[ELF.PHTable.offset_64 : ELF.PHTable.offset_64 + ELF.PHTable.size_64], endianness)
        options['section_header_offset'] = getint(binary[ELF.SHTable.offset_64 : ELF.SHTable.offset_64 + ELF.SHTable.size_64], endianness)
        options['flags'] = getint(binary[ELF.Flags.offset_64 : ELF.Flags.offset_64 + ELF.Flags.size], endianness)
        options['header_size'] = getint(binary[ELF.HeaderSize.offset_64 : ELF.HeaderSize.offset_64 + ELF.HeaderSize.size], endianness)
        options['program_header_entry_size'] = getint(binary[ELF.PHEntrySize.offset_64 : ELF.PHEntrySize.offset_64 + ELF.PHEntrySize.size], endianness)
        options['program_header_entry_num'] = getint(binary[ELF.PHNumber.offset_64 : ELF.PHNumber.offset_64 + ELF.PHNumber.size], endianness)
        options['section_header_entry_size'] = getint(binary[ELF.SHEntrySize.offset_64 : ELF.SHEntrySize.offset_64 + ELF.SHEntrySize.size], endianness)
        options['section_header_entry_num'] = getint(binary[ELF.SHNumber.offset_64 : ELF.SHNumber.offset_64 + ELF.SHNumber.size], endianness)
        options['section_header_str_index'] = getint(binary[ELF.SHStrIndex.offset_64 : ELF.SHStrIndex.offset_64 + ELF.SHStrIndex.size], endianness)
    ### Done parsing ELF Header ###

    ### Parse the Program Header ###
    segments = []
    entry_size = options['program_header_entry_size']
    word_size = 4 if options['class'] == capstone.CS_MODE_32 else 8
    for i in xrange(options['program_header_entry_num']):
        entry_offset = options['program_header_offset'] + i * entry_size
        segment = {}
        segment['p_type']   = getint(binary[entry_offset + word_size * 0 : entry_offset + word_size * 1], endianness)
        segment['p_offset'] = getint(binary[entry_offset + word_size * 1 : entry_offset + word_size * 2], endianness)
        segment['p_vaddr']  = getint(binary[entry_offset + word_size * 2 : entry_offset + word_size * 3], endianness)
        segment['p_paddr']  = getint(binary[entry_offset + word_size * 3 : entry_offset + word_size * 4], endianness)
        segment['p_filesz'] = getint(binary[entry_offset + word_size * 4 : entry_offset + word_size * 5], endianness)
        segment['p_memsz']  = getint(binary[entry_offset + word_size * 5 : entry_offset + word_size * 6], endianness)
        segment['p_flags']  = getint(binary[entry_offset + word_size * 6 : entry_offset + word_size * 7], endianness)
        segment['p_align']  = getint(binary[entry_offset + word_size * 7 : entry_offset + word_size * 8], endianness)
        segments.append(segment)

    ### Parse the Section Header ###
    sections = []
    entry_size = options['section_header_entry_size']
    section_names = ELF.parseSection(binary, options, options['section_header_str_index'], entry_size, word_size, endianness)
    section_names_strings = binary[section_names['sh_offset'] : section_names['sh_offset'] + section_names['sh_size']]
    
    for i in xrange(options['section_header_entry_num']):
        section = ELF.parseSection(binary, options, i, entry_size, word_size, endianness)
        section['sh_name_string'] = section_names_strings[section['sh_name']:].split('\x00')[0]
        sections.append(section)

    sections.sort(key=lambda i: i['sh_offset'])

    options['segments_info'] = segments
    options['sections_info'] = sections
    
    return options

class MagicHeader:
    offset = 0
    size = 4
    value = '\x7F' + 'ELF'
#### END REQUIRED FUNCTIONS ####
class ELF:
    class Class:
        offset = 4
        size = 1

    class Endianness:
        offset = 5
        size = 1

    class OS:
        offset = 7
        size = 1
        values = {
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

    class Type:
        offset = 0x10
        size = 2
        values = {
                1 : 'relocatable',
                2 : 'executable',
                3 : 'shared',
                4 : 'core'
                }

    class Arch:
        offset = 0x12
        size = 2
        values = {
                0x02 : False, # SPARC not yet supported in capstone
                0x03 : capstone.CS_ARCH_X86,
                0x08 : capstone.CS_ARCH_MIPS,
                0x14 : capstone.CS_ARCH_PPC,
                0x28 : capstone.CS_ARCH_ARM,
                0x32 : False, # IA_64 not yet supported in capstone
                0x3E : capstone.CS_ARCH_X86, # This is actually x86_64 which I think is taken care of by the CS_MODE_64
                0xB7 : capstone.CS_ARCH_ARM64
                }

    class EntryPoint:
        offset = 0x18
        size_32 = 4
        size_64 = 8

    class PHTable:
        offset_32 = 0x1C
        offset_64 = 0x20
        size_32 = 4
        size_64 = 8

    class SHTable:
        offset_32 = 0x20
        offset_64 = 0x28
        size_32 = 4
        size_64 = 8

    class Flags:
        offset_32 = 0x24
        offset_64 = 0x30
        size = 4

    class HeaderSize:
        offset_32 = 0x28
        offset_64 = 0x34
        size = 2

    class PHEntrySize:
        offset_32 = 0x2A
        offset_64 = 0x36
        size = 2

    class PHNumber:
        offset_32 = 0x2C
        offset_64 = 0x38
        size = 2

    class SHEntrySize:
        offset_32 = 0x2E
        offset_64 = 0x3A
        size = 2

    class SHNumber:
        offset_32 = 0x30
        offset_64 = 0x3C
        size = 2

    class SHStrIndex:
        offset_32 = 0x32
        offset_64 = 0x3E
        size = 2
    
    @staticmethod
    def parseSection(binary, options, index, entry_size, word_size, endianness):
        entry_offset = options['section_header_offset'] + index * entry_size
        section = {}
        section['sh_name']      = getint(binary[entry_offset : entry_offset + 4], endianness) # Always 4 bytes
        section['sh_type']      = getint(binary[entry_offset + 4 : entry_offset + 8], endianness) # Always 4 bytes
        section['sh_flags']     = getint(binary[entry_offset + 8 : entry_offset + 8 + word_size], endianness) # 32 or 64 bits
        section['sh_addr']      = getint(binary[entry_offset + 8 + word_size : entry_offset + 8 + word_size * 2], endianness) # 32 or 64 bits
        section['sh_offset']    = getint(binary[entry_offset + 8 + word_size * 2: entry_offset + 8 + word_size * 3], endianness) # 32 or 64 bits
        section['sh_size']      = getint(binary[entry_offset + 8 + word_size * 3 : entry_offset + 8 + word_size * 4], endianness) # 32 or 64 bits
        section['sh_link']      = getint(binary[entry_offset + 8 + word_size * 4 : entry_offset + 12 + word_size * 4], endianness) # Always 4 bytes
        section['sh_info']      = getint(binary[entry_offset + 12 + word_size * 4 : entry_offset + 16 + word_size * 4], endianness) # Always 4 bytes
        section['sh_addralign'] = getint(binary[entry_offset + 16 + word_size * 4 : entry_offset + 16 + word_size * 5], endianness) # 32 or 64 bits
        section['sh_entrsize']  = getint(binary[entry_offset + 16 + word_size * 5 : entry_offset + 16 + word_size * 6], endianness) # 32 or 64 bits
        return section

def getint(string, endianness=False):
    if endianness:
        string = string[::-1]
    return int(string.encode('hex'), 16)
