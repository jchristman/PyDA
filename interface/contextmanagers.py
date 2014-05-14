from Tkinter import CURRENT
from tkFont import Font

class WidgetContextManager:
    def __init__(self, app, processing_queue, widget, separator, begin_line, click_string, tags):
        self.app = app
        self.processing_queue = processing_queue
        self.separator = separator
        self.begin_line = begin_line
        self.widget = widget
        self.click_string = click_string
        self.processing_queue = processing_queue

        self.is_line = False
        self.current_line = 0
        
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
            uuid = '%s-%i' % (tag, self.tag_data[tag][0])
            self.tag_data[tag][0] += 1
            return tag, uuid
        except:
            return ''
    
    def click_callback(self, event):
        tags = self.widget.tag_names(CURRENT)
        if len(tags) > 1:
            # Get the menu object and set its context equal to the uuid
            if len(tags) > 2:
                ranges = self.widget.tag_ranges(tags[2])
                for i in xrange(0, len(ranges), 2):
                    start = ranges[i]
                    stop = ranges[i+1]
                    print 'Line clicked is:',repr(self.widget.get(start, stop))

            ranges = self.widget.tag_ranges(tags[1])
            clicked_data = self.widget.get(ranges[0], ranges[1])
            # index = self.widget.data_model.search(clicked_data)
            # print 'Data is at index %i of data model' % index
            menu = self.tag_data[tags[0]][1]
            menu.context = clicked_data
            menu.post(event.x_root + 5, event.y_root + 5)

    def addCallback(self, func, args=None, kwargs=None):
        self.app.addCallback(self.processing_queue, func, args, kwargs)

    def clearQueue(self):
        with self.processing_queue.mutex:
            self.processing_queue.queue.clear()

    def insert(self, index, line):
        line = [x for x in line.split(self.separator) if not x == '']
        if index == '1.0':
            line = line[::-1]
            indices = ('1.0', '2.0')
        else:
            indices = ('end -2 line linestart', 'end -2 line lineend')
        for part in line:
            part_type = self.separator + part[0]
            if part_type == self.begin_line:
                self.is_line = True
                continue
            part = part[1:]
            self.app.addCallback(self.processing_queue, self.widget.insert, (index, part, self.createTags(part_type)))
        if self.is_line:
            self.is_line = False
            self.app.addCallback(self.processing_queue, self.widget.tag_add,
                                 ('%s-%i' % (self.begin_line, self.current_line),
                                  indices[0], indices[1]))
            self.current_line += 1

    def yview_moveto(self, index):
        self.app.addCallback(self.processing_queue, self.widget.yview_moveto, (index,))

