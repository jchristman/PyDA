from capstone import *
from disassembler.formats.common.inst import CommonInstFormat

prologues = {}
epilogues = {}
prologues[CS_ARCH_X86] = {
    CS_MODE_16 : [
        [CommonInstFormat(None, 'push', 'bp', ''), CommonInstFormat(None, 'mov', 'bp, sp', '')], # CDECL/STDCALL/FASTCALL
        [CommonInstFormat(None, 'push', 'bp', ''), CommonInstFormat(None, 'push', 'di', ''), CommonInstFormat(None, 'push', 'si', '')],
    ],
    CS_MODE_32 : [
        [CommonInstFormat(None, 'push', 'ebp', ''), CommonInstFormat(None, 'mov', 'ebp, esp', '')], # CDECL/STDCALL/FASTCALL
        [CommonInstFormat(None, 'push', 'ebp', ''), CommonInstFormat(None, 'push', 'edi', ''), CommonInstFormat(None, 'push', 'esi', '')],

    ],
    CS_MODE_64 : [
        [CommonInstFormat(None, 'push', 'rbp', ''), CommonInstFormat(None, 'mov', 'rbp, rsp', '')], # CDECL/STDCALL/FASTCALL
        [CommonInstFormat(None, 'push', 'rbp', ''), CommonInstFormat(None, 'push', 'rdi', ''), CommonInstFormat(None, 'push', 'rsi', '')],
    ],
}
epilogues[CS_ARCH_X86] = {
    CS_MODE_16 : [
        # [CommonInstFormat(None, 'pop', 'bp', ''), CommonInstFormat(None, 'ret', '', '')], # CDECL/FASTCALL
        # [CommonInstFormat(None, 'leave', '', ''), CommonInstFormat(None, 'ret', '', '')], # CDECL/FASTCALL
        # [CommonInstFormat(None, 'pop', 'bp', ''), CommonInstFormat(None, 'ret', 'WILDCARD', '')], # STDCALL
        # [CommonInstFormat(None, 'leave', '', ''), CommonInstFormat(None, 'ret', 'WILDCARD', '')], # STDCALL
        [CommonInstFormat(None, 'ret', '', '')],
        [CommonInstFormat(None, 'ret', 'WILDCARD', '')], # Really, every function ends with a ret
        [CommonInstFormat(None, 'hlt', '', '')],
        [CommonInstFormat(None, 'rep ret', '', '')],
    ],
    CS_MODE_32 : [
        # [CommonInstFormat(None, 'pop', 'ebp', ''), CommonInstFormat(None, 'ret', '', '')], # CDECL/FASTCALL
        # [CommonInstFormat(None, 'leave', '', ''), CommonInstFormat(None, 'ret', '', '')], # CDECL/FASTCALL
        # [CommonInstFormat(None, 'pop', 'ebp', ''), CommonInstFormat(None, 'ret', 'WILDCARD', '')], # STDCALL
        # [CommonInstFormat(None, 'leave', '', ''), CommonInstFormat(None, 'ret', 'WILDCARD', '')], # STDCALL
        [CommonInstFormat(None, 'ret', '', '')],
        [CommonInstFormat(None, 'ret', 'WILDCARD', '')], # Really, every function ends with a ret
    ],
    CS_MODE_64 : [
        # [CommonInstFormat(None, 'pop', 'rbp', ''), CommonInstFormat(None, 'ret', '', '')], # CDECL/FASTCALL
        # [CommonInstFormat(None, 'leave', '', ''), CommonInstFormat(None, 'ret', '', '')], # CDECL/FASTCALL
        # [CommonInstFormat(None, 'pop', 'rbp', ''), CommonInstFormat(None, 'ret', 'WILDCARD', '')], # STDCALL
        # [CommonInstFormat(None, 'leave', '', ''), CommonInstFormat(None, 'ret', 'WILDCARD', '')], # STDCALL
        [CommonInstFormat(None, 'ret', '', '')],
        [CommonInstFormat(None, 'ret', 'WILDCARD', '')], # Really, every function ends with a ret
    ],
}

# Not yet implemented
prologues[CS_ARCH_MIPS] = {
    CS_MODE_THUMB : [],
    CS_MODE_THUMB : [],
    CS_MODE_THUMB+CS_MODE_BIG_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_BIG_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN : []
}
prologues[CS_ARCH_PPC] = {
    CS_MODE_THUMB : [],
    CS_MODE_THUMB : [],
    CS_MODE_THUMB+CS_MODE_BIG_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_BIG_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN : []
}

prologues[CS_ARCH_ARM] = {
    CS_MODE_THUMB : [],
    CS_MODE_THUMB : [],
    CS_MODE_THUMB+CS_MODE_BIG_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_BIG_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN : []
}

epilogues[CS_ARCH_ARM] = {
    CS_MODE_THUMB : [],
    CS_MODE_THUMB : [],
    CS_MODE_THUMB+CS_MODE_BIG_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_BIG_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN : []
}

prologues[CS_ARCH_ARM64] = {
    CS_MODE_THUMB : [],
    CS_MODE_THUMB : [],
    CS_MODE_THUMB+CS_MODE_BIG_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_BIG_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN : []
}

epilogues[CS_ARCH_ARM64] = {
    CS_MODE_THUMB : [],
    CS_MODE_THUMB : [],
    CS_MODE_THUMB+CS_MODE_BIG_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_BIG_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN : [],
    CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN : []
}
