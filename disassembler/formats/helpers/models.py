def defaultToFunc(obj): yield obj
def defaultFromFunc(string): return string
def defaultSearchFunc(item, data): return None

class DataModel:
    '''
    This DataModel serves as an accessor to some data structure of objects through the use
    of string manipulations. It takes a list and two functions as arguments so that it can
    convert between some object format and strings on the fly. The toFunc must be a generator
    that yield strings or DataModels.
    '''
    def __init__(self, data, toFunc=defaultToFunc, lengthFunc=len, fromFunc=defaultFromFunc, searchFunc=defaultSearchFunc):
        if not isinstance(data, list):
            raise NotAListException()
        self.data = data
        self.toFunc = toFunc
        self.fromFunc = fromFunc
        self.length = lengthFunc # You can pass in a custom length function so that the data model can know its recursive length
        self.current_length = 0
        self.length_changed = False
        self.searchFunc = searchFunc

    def get(self, arg1, arg2=None, arg3=1):
        '''
        The first argument is either the start index or the max number of items. The second
        argument is an optional max number of items. The third argument is an optional
        argument for step direction (1 or -1)
        '''
        if arg2 is None:
            for item in self._get(0, arg1, 1, DataModel.DataModelIndex(0)):
                yield item
        else:
            for item in self._get(arg1, arg2, arg3, DataModel.DataModelIndex(0)):
                yield item

    def _get(self, start_index, max_items, direction, item_start):
        '''
        So this is a super complex function. Basically though, it asks each node in the
        DataModel how long it is so that it can pick the appropriate node to start drilling
        down to the next data to yield. It is basically hell on earth, but assuming that
        the passed in lengthFunc provides an accurate measure of how long each child of that
        node is, this function will work and yield the appropriate items...
        '''
        print start_index, max_items, direction, item_start.val
        count = 0
        for item in self:
            if count >= max_items: return
            if type(item) is str: item_length = 1
            else: item_length = self.length(item) # Can be a custom function here
            #print 'Start Index:',start_index,'Item Start:',item_start.val,'Length:',item_length
            if (start_index < item_start.val + item_length and direction == 1) or (start_index > item_start.val + item_length and direction == -1): # If we are past the start index, then we should start to get items!
                if type(item) is str:
                    item_start.val += 1
                    count += 1
                    yield item
                else:
                    for sub_item in self.toFunc(item):
                        if count >= max_items: return
                        if isinstance(sub_item, DataModel):
                            for sub_dm_item in sub_item._get(start_index, max_items - count, direction, item_start):
                                count += 1
                                yield sub_dm_item
                        else:
                            item_start.val += 1
                            if item_start.val <= start_index:
                                continue # because we aren't to the correct item yet
                            count += 1
                            yield sub_item
            else:
                item_start.val += item_length

    def set(self, index, item):
        '''
        This function will recursively drill to the correct item as references by
        index and set the item using the fromFunc. 
        '''
        pass

    def search(self, data, convert=True):
        '''
        This function should return an index of the item within the overall context
        of the DataModel. It will return the first occurence of the data.
        '''
        if convert: data = self.fromFunc(data)
        offset = 0
        index = None
        for item in self:
            if type(item) is str: offset += 1; continue
            index = self.searchFunc(item, data)
            if index:
                index += offset # To give the total offset in the data structure
                break
            offset += self.length(item)
        return index
                            
    def append(self, item, isStr=False):
        self.length_changed = True
        if isStr:   self.data.append(self.fromFunc(item))
        else:       self.data.append(item)

    def __len__(self):
        if self.length_changed:
            self.current_length = sum(1 if type(x) is str else self.length(x) for x in self.data) # Recursively sum the size of the root node
            self.length_changed = False
        return self.current_length

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

    def __delitem__(self, key):
        self.data = self.data[:key] + self.data[key + 1:]

    class DataModelIndex:
        def __init__(self, val):
            self.val = val

class NotAListException(Exception):
    pass

if __name__ == '__main__':
    class Test:
        def __init__(self, depth):
            self.depth = depth
            if depth < 15:
                self.data_model = DataModel([Test(2*depth), Test(3*depth)], Test.test, Test.recursiveLength)
            else:
                self.data_model = ['done']
            
        @staticmethod
        def test(item):
            array = [item.depth, item.data_model]
            for i in array:
                yield i

        @staticmethod
        def recursiveLength(item):
            return 1 + sum(Test.recursiveLength(i) if isinstance(i, Test) else 1 for i in item.data_model)

    import sys
    t = Test(1)
    for i in t.data_model.get(int(sys.argv[1]),int(sys.argv[2])):
        print 'Item:',i
