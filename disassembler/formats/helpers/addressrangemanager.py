'''
An AddressRangeManager
'''

import copy

class AddressRangeManager:
    # Note: start and end bounds are inclusive
    def __init__(self, start, end, default_format='t'):
        self.start = start
        self.end = end
        self.ranges = [AddressRange(self.start, self.end, default_format)]

    def setText(self, start, end):
        self._set(start, end, "t")

    def setData(self, start, end):
        self._set(start, end, "d")

    def _set(self, start, end, format):
        new_range = AddressRange(start, end, format)
        for index, r in enumerate(self.ranges):
            if start in r or end in r or r.start in new_range or r.end in new_range:
                self.ranges[index] = r.split(new_range)
        
        self.ranges = self._flattenRanges(self.ranges)
        self._combineSimilar()

    def _combineSimilar(self):
        index = 0
        start_streak = 0
        streak = []
        while index < len(self.ranges):
            if index != len(self.ranges)-1 and self.ranges[index].format == self.ranges[index+1].format:
                if len(streak) == 0:
                    start_streak = index
                    streak.append(self.ranges[index])
                
                streak.append(self.ranges[index+1])
            else:
                if len(streak) > 0:
                    self.ranges[start_streak] = AddressRange.combine(streak)
                    for x in xrange(start_streak+1, start_streak+len(streak)):
                        self.ranges[x] = None
                    streak = []
            index += 1

        self.ranges = [x for x in self.ranges if not x is None]

    def _flattenRanges(self, x):
        result = []
        for el in x:
            if hasattr(el, "__iter__") and not isinstance(el, AddressRange):
                result.extend(self._flattenRanges(el))
            else:
                result.append(el)
        return result

    def __getitem__(self, address):
        if not type(address) is int:
            print 'argument to getitem was not an int'
            return False
        else:
            for r in self.ranges:
                if address in r:
                    return r

    def __contains__(self, address):
        if not type(address) is int:
            print 'argument to contains was not an int'
            return False
        else:
            return self.start <= address <= self.end


class AddressRange:
    # Note: start and end bounds are inclusive
    def __init__(self, start, end, format):
        self.start = start
        self.end = end
        self.format = format

    def __contains__(self, address):
        if not type(address) is int:
            print 'argument to contains was not an int'
            return False
        else:
            return self.start <= address <= self.end

    def isText(self):
        return self.format == 't'
    def isData(self):
        return self.format == 'd'   

    def __str__(self):
        return str([hex(self.start), hex(self.end), self.format])

    def split(self, new_range):
        s = self.start
        ns = new_range.start
        e = self.end
        ne = new_range.end
        f = self.format
        nf = new_range.format

        if s == ns: # Both start at the same address
            if e == ne: # Ends at the same address
                return [AddressRange(s, e, nf)]
            if e < ne: # Ends past the last address in this range
                return [AddressRange(s, e, nf)]
            if e > ne: # Ends before the end of this range
                return [AddressRange(s, ne, nf), AddressRange(ne+1, e, f)]
        elif s < ns: # The new range starts in the middle of this one
            if e == ne: # Ends at the same end as this range
                return [AddressRange(s, ns-1, f), AddressRange(ns, e, nf)]
            if e < ne: # Ends past the last address in this range
                return [AddressRange(s, ns-1, f), AddressRange(ns, e, nf)]
            if e > ne: # Ends before the end of this range
                return [AddressRange(s, ns-1, f), AddressRange(ns, ne, nf), AddressRange(ne+1, e, f)]
        elif s > ns: # The new range started before this one
            if e == ne: # Ends at the same address
                return [AddressRange(s, e, nf)]
            if e < ne: # Ends past the last address in this range
                return [AddressRange(s, e, nf)]
            if e > ne: # Ends before the end of this range
                return [AddressRange(s, ne, nf), AddressRange(ne+1, e, f)]

    @staticmethod
    def combine(ranges):
        return AddressRange(ranges[0].start, ranges[-1].end, ranges[0].format)

def pr(r):
    print [str(x) for x in man.ranges]

if __name__ == '__main__':
    man = AddressRangeManager(0x1000, 0x2000)
    pr(man.ranges)
    man.setData(0x1000, 0x1200)
    pr(man.ranges)
    man.setText(0x1090, 0x1210)
    pr(man.ranges)
    man.setText(0x1000, 0x1100)
    pr(man.ranges)
    man.setData(0x1200, 0x1400)
    pr(man.ranges)
    print man[0x1401].isData()
