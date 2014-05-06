from Tkinter import CURRENT
from tkFont import Font

class WidgetClickContextManager:
    def __init__(self, app, processing_queue, separator, widget, click_string, callback, tags):
        self.app = app
        self.processing_queue = processing_queue
        self.separator = separator
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

    def addCallback(self, func, args=None, kwargs=None):
        self.app.addCallback(self.processing_queue, func, args, kwargs)

    def clearQueue(self):
        with self.processing_queue.mutex:
            self.processing_queue.queue.clear()

    def insert(self, index, line):
        line = [x for x in line.split(self.separator) if not x == '']
        if index == '1.0': line = line[::-1]
        for part in line:
            part_type = self.separator + part[0]
            part = part[1:]
            self.app.addCallback(self.processing_queue, self.widget.insert, (index, part, self.createTags(part_type)))

    def yview_moveto(self, index):
        self.app.addCallback(self.processing_queue, self.widget.yview_moveto, (index,))

    def addTagToBindings(self, tag, callback, foreground, click_string):
        self.widget.tag_config(tag, foreground=foreground)
        self.widget.tag_bind(tag, click_string, callback)
        self.tag_data[tag] = 0

    def click_callback(self, event):
        for uuid in self.widget.tag_names(CURRENT)[1:]:
            self.callback(uuid)
            return
