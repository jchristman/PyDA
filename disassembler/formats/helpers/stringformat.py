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