import struct
from disassembler.formats.helpers.label import Label

class CommonInstFormat:
    def __init__(self, address, mnemonic, op_str, bytes, comment=None):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.bytes = bytes
        self.function = None
        self.comment = comment

    def getByteString(self, num_bytes):
        string_size = num_bytes*3
        unpadded = str(self.bytes).encode("hex")[0:num_bytes*2]
        return ' '.join([unpadded[x:x+2] for x in xrange(0, len(unpadded), 2)]).ljust(string_size)

    def toString(self, beg_tag, section_tag, section_name, address_tag, 
                    bytes_tag, num_bytes, mnemonic_tag, op_str_tag, comment_tag, end_tag):
        return '%s%s%s: %s0x%x \t %s%s \t %s%s  %s%s  %s%s %s\n' % (
                    beg_tag,
                    section_tag, section_name, 
                    address_tag, self.address,
                    bytes_tag, self.getByteString(num_bytes), 
                    mnemonic_tag, self.mnemonic, 
                    op_str_tag, self.op_str,
                    comment_tag, '' if self.comment is None else '; %s' % self.comment,
                    end_tag
                    )

    def isRepresentedByString(self, some_string):
        # features are all things that must be present in the line
        features = ['0x%x' % self.address, self.mnemonic, self.op_str]
        if all(x in some_string for x in features):
            # Make sure it doesn't just coincidentally match (eg. in a comment)
            if sum(len(x) for x in features) + 15 > len(some_string):
                return True
        return False

    def __len__(self):
        return 1 # the number of lines an instruction takes up

    @staticmethod
    def length(inst):
        return 1

    # @staticmethod
    # def toString(inst):
    #     pass
