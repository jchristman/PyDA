from disassembler.formats.common.inst import CommonInstFormat
from disassembler.formats.helpers.exceptions import ImproperObjectType

class InstComparator:
    '''
    Can be used to compare the passed in CommonInstFormat object with any other
    CommonInstFormat object. This class must be subclassed before it can be used
    and the child must implement the equals method for finding which fields to compare
    on.
    '''
    def __init__(self, inst):
        if not isinstance(inst, CommonInstFormat):
            raise ImproperObjectType('InstComparator must be constructed with a CommonInstFormat object')
        self.inst = inst
        self.match = None

    def __eq__(self, other):
        if not isinstance(other, CommonInstFormat):
            return False
        result = self.equals(other)
        if result:
            self.match = other
        return result
    
    def __getattr__(self, name):  # support hash() or anything else needed by __contains__
        return getattr(self.inst, name)

    def equals(self, other):
        raise NotImplementedError('Child class does not implement and equals method')

class AddressComparator(InstComparator):
    def equals(self, other):
        return self.inst.address == other.address

class MnemonicComparator(InstComparator):
    def equals(self, other):
        return self.inst.mnemonic == other.mnemonic

class OpStrComparator(InstComparator):
    def equals(self, other):
        return self.inst.op_str == other.op_str
    
class BytesComparator(InstComparator):
    def equals(self, other):
        return self.inst.bytes == other.bytes

class CommentComparator(InstComparator):
    def equals(self, other):
        return self.inst.comment == other.comment
