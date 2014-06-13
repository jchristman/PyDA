from Tkinter import CURRENT
from tkFont import Font
from guielements import QuickElementFactory

class WidgetContextManager:
    def __init__(self, app, processing_queue, widget, click_string):
        self.app = app
        self.processing_queue = processing_queue
        self.widget = widget
        self.click_string = click_string

    def addCallback(self, func, args=None, kwargs=None):
        self.app.addCallback(self.processing_queue, func, args, kwargs)

    def clearQueue(self):
        with self.processing_queue.mutex:
            self.processing_queue.queue.clear()

    def yview_moveto(self, index):
        self.app.addCallback(self.processing_queue, self.widget.yview_moveto, (index,))


class AssemblyTextboxContextManager(WidgetContextManager):
    def __init__(self, app, disassembly, interface, processing_queue, widget, separator, begin_line, click_string, tags):
        WidgetContextManager.__init__(self, app, processing_queue, widget, click_string)
        self.app = app
        self.disassembly = disassembly
        self.interface = interface
        self.separator = separator
        self.begin_line = begin_line
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
        self.widget.mark_set('insert', 'current') # move the cursor to mouse position

        tags = self.widget.tag_names(CURRENT)
        if len(tags) > 1:
            # Get the menu object and set its context equal to the uuid
            if len(tags) > 2:
                ranges = self.widget.tag_ranges(tags[2])
                for i in xrange(0, len(ranges), 2):
                    start = ranges[i]
                    stop = ranges[i+1]
                    print 'Line clicked is:',repr(self.widget.get(start, stop))
                    line = str(self.widget.get(start, stop))

            ranges = self.widget.tag_ranges(tags[1])
            clicked_data = self.widget.get(ranges[0], ranges[1])
            # index = self.widget.data_model.search(clicked_data, key=self.widget.key)
            # print 'Data is at index %i of data model' % index
            menu = self.tag_data[tags[0]][1]
            menu.context = clicked_data # this is the info that gets read by the callback
            menu.post(event.x_root + 5, event.y_root + 5)

    def insert(self, index, line):
        try: line = [x for x in line.split(self.separator) if not x == '']
        except: return
        
        if len(line) == 1:
            self.app.addCallback(self.processing_queue, self.widget.insert, (index, line[0]))
            return
        if index == '1.0':
            line = line[::-1]
            indices = ('1.0', '2.0')
        else:
            indices = ('end -2 line linestart', 'end -2 line lineend')
            # indices = ('end -2 line linestart', 'end -1 line linestart')
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

    def controlKeyHeld(self, event):
        return event.state & 0x004 # see here: http://infohost.nmt.edu/tcc/help/pubs/tkinter/web/event-handlers.html

    def keyHandler(self, event):
        # print event.keysym
        c = event.char
        if c == ';':
            self.comment(event)
        elif c == 'n' or c == 'N':
            self.renameLabel(event)
        elif event.keysym in ['Up', 'Down', 'Left', 'Right', 'Next', 'Prior', 'End', 'Home']:
            return
        elif event.keysym == 'Escape':
            self.interface.popLastLocation()
        elif self.controlKeyHeld(event):
            if event.keysym == 'a':
                textbox = self.widget
                textbox.tag_add('sel', '1.0', 'end')
            elif event.keysym == 'c':
                self.app.clipboard_clear()
                self.app.clipboard_append(self.widget.selection_get())
            elif event.keysym == 'o':
                self.interface.onDisassembleFile()
            elif event.keysym == 'q':
                self.interface.onExit()
            elif event.keysym == 's':
                self.interface.onSave()
            elif event.keysym == 'Tab':
                return 'break'

        # Otherwise, don't let this key go to the screen
        return 'break'

    def comment(self, event):
        if not self.app.disassembler.isInitialized():
            return # Nothing is loaded yet

        textbox = self.widget
        e, tl = None, None

        def addComment(*args):
            if e is None or tl is None:
                return
            comment = e.get()
            contents = textbox.getCurrentLine()
            index = int(float(textbox.getCurrentRowIndex())) + textbox.getCurrentDataOffset()
            result = self.app.disassembler.setCommentForLine(contents, index, comment)
            if result:
                tb_index = textbox.getCurrentRowIndex()
                textbox.redrawLine(tb_index)

            tl.destroy()

        e, tl = QuickElementFactory.createTextInputBox(self.app, "Insert Comment", "Please enter a comment:", "Add Comment", addComment)


    def renameLabel(self, event):
        if not self.app.disassembler.isInitialized():
            return

        textbox = self.widget
        e, tl = None, None

        def rename(*args):
            if e is None or tl is None:
                return
            new_name = e.get()
            contents = textbox.getCurrentLine()
            result = self.app.disassembler.renameLabel(contents, new_name)
            if result:
                textbox.redrawLine(textbox.getCurrentRowIndex())
                self.interface.reloadFunctions()
                self.interface.reloadStrings()

            tl.destroy()

        e, tl = QuickElementFactory.createTextInputBox(self.app, 'Rename Label', 'Please enter a new name:', "Rename", rename)