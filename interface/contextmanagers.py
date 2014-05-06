from Tkinter import CURRENT
from tkFont import Font

class WidgetClickContextManager:
    def __init__(self, app, processing_queue, widget, separator, click_string, tags):
        self.app = app
        self.processing_queue = processing_queue
        self.separator = separator
        self.widget = widget
        self.click_string = click_string
        self.processing_queue = processing_queue

        self.tag_data = {}
        for tag, foreground, context_menu in tags:
            self.addTagToBindings(tag, foreground, context_menu, self.click_callback)

    def addTagToBindings(self, tag, foreground, context_menu, callback):
        self.widget.tag_config(tag, foreground=foreground)
        if context_menu:
            self.widget.tag_bind(tag, self.click_string, callback)
        self.tag_data[tag] = [0, context_menu]

    def createTags(self, tag):
        try:
            # These next three lines calculate a UUID for the current chunk of data that we are tagging
            print self.tag_data[tag]
            uuid = '%s-%i' % (tag, self.tag_data[tag][0])
            self.tag_data[tag][0] += 1
            return tag, uuid
        except:
            return '',''
    
    def click_callback(self, event):
        tags = self.widget.tag_names(CURRENT)
        if len(tags) > 1:
            # Get the menu object and set its context equal to the uuid
            menu = self.tag_data[tags[0]][1]
            menu.context = tags[0]
            menu.post(event.x_root, event.y_root)

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
