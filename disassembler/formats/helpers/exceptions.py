class BadMagicHeaderException(Exception):
    pass

class ImproperObjectType(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)

class ImproperParameterException(Exception):
    def __init__(self, message):
        Exception.__init__(self, message)
