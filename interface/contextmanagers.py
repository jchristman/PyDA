from Tkinter import CURRENT
from tkFont import Font
from settings import PYDA_SEP #, PYDA_SECTION, PYDA_ADDRESS, PYDA_MNEMONIC, PYDA_OP_STR, PYDA_COMMENT, PYDA_GENERIC, PYDA_ENDL

class WidgetClickContextManager:
    def __init__(self, widget, click_string, callback, asyncExecCallback, tags):
        self.widget = widget # This is the Tkinter text object that we want to add special stuff to
        self.callback = callback
        self.asyncExecCallback = asyncExecCallback

        self.tag_data = {}
        for tag,foreground in tags:
            self.addTagToBindings(tag, self.click_callback, foreground, click_string)

    def createTags(self, tag):
        try:
            # These next three lines calculate a UUID for the current chunk of data that we are tagging
            uuid = '%s-%i' % (tag, self.tag_data[tag])
            self.tag_data[tag] += 1
            return tag, uuid
        except:
            return '',''

    def insert(self, widget, index, line):
        line = [x for x in line.split(PYDA_SEP) if not x == '']
        for part in line:
            part_type = PYDA_SEP + part[0]
            part = part[1:]
            self.asyncExecCallback(widget.insert, (index, part, self.createTags(part_type)))

    def addTagToBindings(self, tag, callback, foreground, click_string):
        self.widget.tag_config(tag, foreground=foreground)
        self.widget.tag_bind(tag, click_string, callback)
        self.tag_data[tag] = 0

    def click_callback(self, event):
        for uuid in self.widget.tag_names(CURRENT)[1:]:
            self.callback(uuid)
            return
