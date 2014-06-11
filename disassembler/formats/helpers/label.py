'''
Author: Frank Adkins

Representation of a label object. Intended to be a renamable
tag within disassembled code for easy reference.
'''

class Label:
    LABEL_SYMBOL = ': '

    def __init__(self, address, name, item, xrefs=None):
        self.address = address
        self.name = name
        self.item = item
        self.xrefs = [] if xrefs is None else xrefs

    def __str__(self):
        return self.name

    def toString(self, beg_tag, section_tag, section_name, address_tag, label_tag, end_tag):
        data = '%s%s%s: %s0x%x%s\n' % (
                    beg_tag, section_tag, 
                    section_name, address_tag,
                    self.address,end_tag) # Empty newline
        data += '%s%s%s: %s0x%x%s %s %s\n' % (
                    beg_tag, section_tag, section_name,
                    address_tag, self.address,
                    label_tag, self.nameRep(),
                    end_tag) # The text label itself
        return data

    def isRepresentedByString(self, some_string):
        # features are all things that must be present in the line
        features = ['0x%x' % self.address, self.nameRep()]
        if all(x in some_string for x in features):
            # Make sure it doesn't just coincidentally match (eg. label name in a comment)
            if sum(len(x) for x in features) + 5 > len(some_string):
                return True
        return False

    def nameRep(self):
        return self.name + self.LABEL_SYMBOL

    def __len__(self):
        return 2 # the number of lines a label takes up

    @staticmethod
    def length(inst):
        return 2
