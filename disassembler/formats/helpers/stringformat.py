'''
Author: Frank Adkins

This is a simple object format to manage the strings found 
within an executable. Not much more to say about that.
'''


class StringFormat:
    def __init__(self, addr, name, contents):
        self.address = addr
        self.name = name
        self.contents = contents
        self.length = len(contents)

    def getByteString(self, num_bytes):
        string_size = num_bytes*3
        unpadded = str(self.contents).encode("hex")[0:num_bytes*2]
        return ' '.join([unpadded[x:x+2] for x in xrange(0, len(unpadded), 2)]).ljust(string_size)