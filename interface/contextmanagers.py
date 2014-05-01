from Tkinter import CURRENT
from tkFont import Font
from settings import PYDA_SEP #, PYDA_SECTION, PYDA_ADDRESS, PYDA_MNEMONIC, PYDA_OP_STR, PYDA_COMMENT, PYDA_GENERIC, PYDA_ENDL

class WidgetClickContextManager:
    def __init__(self, app, processing_queue, widget, click_string, callback, tags):
        self.app = app
        self.processing_queue = processing_queue
        self.widget = widget
        self.callback = callback
        self.processing_queue = processing_queue

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

    def clearQueue(self):
        with self.processing_queue.mutex:
            self.processing_queue.queue.clear()

    def insert(self, widget, index, line):
        line = [x for x in line.split(PYDA_SEP) if not x == '']
        for part in line:
            part_type = PYDA_SEP + part[0]
            part = part[1:]
            self.app.addCallback(self.processing_queue, widget.insert, (index, part, self.createTags(part_type)))

    def addTagToBindings(self, tag, callback, foreground, click_string):
        self.widget.tag_config(tag, foreground=foreground)
        self.widget.tag_bind(tag, click_string, callback)
        self.tag_data[tag] = 0

    def click_callback(self, event):
        for uuid in self.widget.tag_names(CURRENT)[1:]:
            self.callback(uuid)
            return
