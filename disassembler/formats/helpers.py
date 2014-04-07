import struct

BYTE = 1    # 8 bits
HWORD = 2   # 16 bits
WORD = 4    # 32 bits
DWORD = 8   # 64 bits

class BadMagicHeaderException(Exception):
    pass
