'''
Author: Frank Adkins

Representation of a label object. Intended to be a renamable
tag within disassembled code for easy reference.
'''

class Label:
    def __init__(self, address, name, item, xrefs=None):
        self.address = address
        self.name = name
        self.item = item
        self.xrefs = [] if xrefs is None else xrefs

    def __str__(self):
    	return self.name
