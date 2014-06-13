'''
Author: Frank Adkins

This is a very simple standardized format for the flags
associated with different parts of an executable (ex. Sections).
'''


class Flags:
    def __init__(self, flags):
        self.read = "r" in flags.lower()
        self.write = "w" in flags.lower()
        self.execute = "x" in flags.lower()

    def __str__(self):
        properties = []
        if self.read:
            properties.append("READ")
        if self.write:
            properties.append("WRITE")
        if self.execute:
            properties.append("EXECUTE")

        return "/".join(properties)