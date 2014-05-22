class AbstractDataModel:
    '''
    This is an abstract implementation of a class for a textbox gui to access a text structure
    '''
    def get(self, arg1, arg2=None, arg3=1, key=None):
        '''
        This method takes in optionally 4 parameters and should behave like xrange. arg1 is
        just the number of items to get when it's the only argument or the start index when
        there is more than one argument. arg2 is an optional argument that will be the end index
        (non-inclusive) to get. arg3 is the optional direction (-1 implies a backward iteration).
        key is an optional argument that can be passed if there are multiple objects that need
        to access the text structure and you need to demultiplex them to different parts of your
        text structure. It should yield the items as a generator.
        '''
        raise NotImplementedError

    def getitem(self, index, key=None):
        '''
        This method will get a single item
        '''
        raise NotImplementedError

    def set(self, index, item, key=None):
        '''
        Should set the index equal to the item
        '''
        raise NotImplementedError

    def append(self, item, key=None):
        '''
        Should append the item to the text structure. This will not necessarily be called on a 
        read/modify accessor vs a read/modify/append accessor. If you don't think you need it,
        don't implement it!
        '''
        raise NotImplementedError

    def search(self, string, key=None):
        '''
        Should be return an object from the text structure.
        '''
        raise NotImplementedError
                            
    def length(self, key=None):
        '''
        This needs to be implemented for the textbox to use as a .length() function
        '''
        raise NotImplementedError

class TextModel(AbstractDataModel):
    def __init__(self):
        self.text = []

    def get(self, arg1, arg2=None, arg3=1, key=None):
        if arg2 is None:
            arg2 = arg1
            arg1 = 0
        data = []
        data_range = xrange(arg1, arg2, arg3)
        for i,line in enumerate(self.text):
            if i in data_range:
                data.append(line)
        return data if arg3 == 1 else reversed(data)

    def getitem(self, index, key=None):
        if index < len(self.text):
            return self.text[index]
        else:
            return None

    def set(self, index, item, key=None):
        self.text[index] = item

    def append(self, item, key=None):
        self.text.append(item)

    def search(self, string, key=None):
        return self.text.index(string)

    def length(self, key=None):
        return len(self.text)

if __name__ == '__main__':
    tm = TextModel()
    tm.append('1')
    tm.append('2')
    tm.append('3')
    print ', '.join(tm.get(0,3))
    print ', '.join(tm.get(3))
    tm.set(2, 'newitem')
    tm.append('newitem2')
    print ', '.join(tm.get(3,-1,-1))
    print tm.search('newitem')

