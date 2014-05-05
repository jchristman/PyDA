'''
Author: Frank Adkins

A StringFinder locates all ctype null-terminated strings within a 
sequence of bytes and returns a list of properly constructed
StringFormat objects.
'''


import re
from stringformat import StringFormat

class StringFinder:
    def __init__(self, addr, bytes):
        self.address = addr
        self.bytes = bytes

    def findStrings(self, length=5):
        # assumes ctype \x00 terminated strings
        pattern = re.compile(r"[\x20-\x7e]{%d,}\x00" % length) 

        strings = []
        for x in pattern.finditer(self.bytes):
            contents = bytearray(x.group())
            name = x.group()[:-1]
            addr = self.address + x.start()
            strings.append(StringFormat(addr, name, contents))

        return strings