'''
Author: Joshua Christman

This file contains many classes to make the code in the main interface much more readable.
It also adds many convenience functions to code to make access easier.
'''

from Tkinter import Menu, Button, Label, Text, Listbox, Scrollbar, Entry, PanedWindow as pw, Frame as fm, INSERT, END, DISABLED, NORMAL
from ttk import Progressbar, Notebook as nb

START = '1.0'

class MenuBar(Menu):
    '''
    Arguments:
    parent - the Tkinter master
    kwargs - optional keyword arguments to be passed to the MenuBar superclass

    Description:
    A custom subclass of Menu that allows easy customization of a menu bar in a Tkinter App
    '''
    def __init__(self, parent, **kwargs):
        Menu.__init__(self, parent, **kwargs)
        parent.config(menu=self)
        self.menus = {}

    def addMenu(self, label):
        '''
        Arguments:
        label - a string that will let you identify the specific menu for adding items to it.

        Description:
        Use this function to add menus to the menu bar.
        '''
        self.menus[label] = Menu(self, tearoff=False)
        self.add_cascade(label=label, menu=self.menus[label])

    def addMenuItem(self, parent_label, label, callback):
        '''
        Arguments:
        parent_label - a string that identifies the parent of this menu item
        label - a string to identify this menu item
        callback - a function pointer that will be called on clicking of the menu item

        Description:
        Adds menu items to a menu
        '''
        self.menus[parent_label].add_command(label=label, command=callback)

    def addMenuSeparator(self, parent_label):
        '''
        Arguments:
        parent_label - a string that identifies the parent menu for the seperator
        '''
        self.menus[parent_label].add_separator()

class ToolBar(fm):
    '''
    Arguments:
    parent - the Tkinter master
    pack_location - location of the tool bar within the master
    kwargs - optional keyword arguments ot be passed to the Frame superclass

    Description:
    A container class that provide convenience functions for a toolbar.
    '''
    def __init__(self, parent, pack_location, **kwargs):
        fm.__init__(self, parent, **kwargs)
        self.pack(side=pack_location, fill='x')
        self.elements = {}

    def addElement(self, element, pack_side):
        '''
        Arguments:
        element - a tkinter widget

        Description:
        Add the element to the PanedWindow
        '''
        uuid = len(self.elements)
        self.elements[uuid] = element
        self.elements[uuid].pack(side=pack_side)
        return self.elements[uuid]
        
    def addButton(self, text, callback, pack_side):
        '''
        Arguments:
        text - the string that will be on the button
        callback - the function that will called when pressed
        pack_side - the side in which the button will be packed

        Descriptions:
        Adds a button to the toolbar.
        '''
        return self.addElement(Button(self, text=text, borderwidth=1, command=callback), pack_side)

    def addLabel(self, text, pack_side):
        '''
        Arguments:
        text - the string that will be displayed on the label
        pack_side - the side in which the label will be packed

        Description:
        Adds a label to the toolbar.
        '''
        return self.addElement(Label(self, text=text), pack_side)

    def addVertSeperator(self, pack_side):
        '''
        Arguments:
        pack_side - the side in which the vertical seperator will be packed

        Description:
        Adds a vertical seperator to the toolbar
        '''
        padding = 4
        self.addElement(Frame(self, width=padding), pack_side)
        self.addElement(Frame(self, height=20, width=1, background='darkgray'), pack_side)
        self.addElement(Frame(self, width=padding), pack_side)

    def addProgressBar(self, pack_side, **kwargs):
        '''
        Arguments:
        pack_side - the side in which the Progressbar will be packed
        kwargs - optional keyword arguments

        Description:
        Adds a Progressbar to the toolbar.
        '''
        return self.addElement(Progressbar(self, **kwargs), pack_side)

class PanedWindow(pw):
    '''
    Arguments:
    parent - the Tkinter master object
    pack_location - the side of the master to pack into
    kwargs - keyword arguments to go to the superclass constructor

    Description:
    A subclass of the Tkinter PanedWindow with some convenience methods
    '''
    def __init__(self, parent, pack_location=None, **kwargs):
        pw.__init__(self, parent, **kwargs)
        if pack_location:
            self.pack(side=pack_location, fill='both', expand=True)
        self.elements = {}

    def addElement(self, element):
        '''
        Arguments:
        element - a tkinter widget

        Description:
        Add the element to the PanedWindow
        '''
        uuid = len(self.elements)
        self.elements[uuid] = element
        self.add(self.elements[uuid])
        return self.elements[uuid]

    def addPanedWindow(self, **kwargs):
        '''
        Arguments:
        pack_location - where to pack the paned window
        kwargs - keyword arguments to be passwed to constructor

        Description:
        Adds a paned window to the paned window
        '''
        return self.addElement(PanedWindow(self, **kwargs))

    def addNotebook(self, **kwargs):
        '''
        Arguments:
        kwargs - keyword arguments to be passwed to constructor

        Description:
        Adds a notebook to the paned window
        '''
        return self.addElement(Notebook(self, **kwargs))

class Notebook(nb):
    '''
    Arguments:
    parent - the Tkinter master widget

    Description:
    A subclass of the ttk notebook
    '''
    def __init__(self, parent, **kwargs):
        nb.__init__(self, parent, **kwargs)
        self.elements = {}
        self.enable_traversal()

    def addElement(self, element, text):
        '''
        Arguments:
        element - a tkinter widget

        Description:
        Add the element to the PanedWindow
        '''
        uuid = len(self.elements)
        self.elements[uuid] = element
        self.add(element, text=text)
        return self.elements[uuid]

    def addFrame(self, text):
        '''
        Arguments:
        text - the label for the frame

        Description:
        Add a frame with a label for the notebook
        '''
        return self.addElement(Frame(self), text)

    def addListboxWithScrollbar(self, text, **kwargs):
        '''
        Arguments:
        text - the label for the notebook tab
        kwargs - keyword arguments for the listbox

        Description:
        Add a listbox with a label for the notebook
        '''
        return self.addFrame(text).addListboxWithScrollbar(**kwargs)

    def addTextboxWithScrollbar(self, text, pack_location=None, fill='both', expand='true', **kwargs):
        '''
        Arguments:
        text - the label for the notebook tab
        kwargs - keyword arguments for the textbox

        Description:
        Add a textbox with a label for the notebook
        '''
        return self.addFrame(text).addTextboxWithScrollbar(**kwargs)

class Frame(fm):
    def __init__(self, parent, pack_location=None, fill='both', expand=True, **kwargs):
        fm.__init__(self, parent, **kwargs)
        self.elements = {}
        if pack_location:
            self.pack(side=pack_location, fill=fill, expand=expand)

    def addElement(self, element, pack_side, fill, expand):
        '''
        Arguments:
        element - a tkinter widget

        Description:
        Add the element to the Frame
        '''
        uuid = len(self.elements)
        self.elements[uuid] = element
        self.elements[uuid].pack(side=pack_side, fill=fill, expand=expand)
        return self.elements[uuid]

    def addFrame(self, pack_side, fill, expand, **kwargs):
        '''
        Arguments:
        pack_side - side to pack into the frame. Defaults to left.
        fill - which directions to fill to. defaults to both.
        expand - whether to expand the element. defaults to True.
        kwargs - for the construction of the Textbox

        Description:
        Add a Textbox to the Frame
        '''
        return self.addElement(Frame(self, **kwargs), pack_side, fill, expand)

    def addTextbox(self, pack_side='left', fill='both', expand=True, **kwargs):
        '''
        Arguments:
        pack_side - side to pack into the frame. Defaults to left.
        fill - which directions to fill to. defaults to both.
        expand - whether to expand the element. defaults to True.
        kwargs - for the construction of the Textbox

        Description:
        Add a Textbox to the Frame
        '''
        return self.addElement(Textbox(self, **kwargs), pack_side, fill, expand)

    def addListbox(self, pack_side='left', fill='both', expand=True, **kwargs):
        '''
        Arguments:
        pack_side - side to pack into the frame. Defaults to left.
        fill - which directions to fill to. defaults to both.
        expand - whether to expand the element. defaults to True.
        kwargs - for the construction of the listbox 

        Description:
        Add a Listbox to the Frame
        '''
        return self.addElement(Listbox(self, **kwargs), pack_side, fill, expand)

    def addScrollbar(self, pack_side='right', fill='y', expand=False, **kwargs):
        '''
        Arguments:
        pack_side - side to pack into the frame. Defaults to right.
        fill - which directions to fill to. defaults to y.
        expand - whether to expand the element. defaults to True.
        kwargs - for the construction of the Scrollbar

        Description:
        Add a Scrollbar to the Frame
        '''
        return self.addElement(Scrollbar(self, **kwargs), pack_side, fill, expand)

    def addEntry(self, pack_side='bottom', fill='x', expand=True, **kwargs):
        '''
        Arguments:
        pack_side - side to pack into the frame. Defaults to bottom.
        fill - which directions to fill to. defaults to x.
        expand - whether to expand the element. defaults to True.
        kwargs - for the construction of the Entry

        Description:
        Add a Entry to the Frame
        '''
        return self.addElement(Entry(self, **kwargs), pack_side, fill, expand)

    def addLabel(self, text, pack_side='left'):
        '''
        Arguments:
        text - the string to put in the label
        pack_side - side to pack into the frame. Defaults to left.
        kwargs - for the construction of the Scrollbar

        Description:
        Add a Label to the Frame
        '''
        return self.addElement(Label(self, text=text), pack_side, 'none', False)

    def addEntryWithLabel(self, text, pack_side, fill, expand, **kwargs):
        '''
        Arguments:
        text - the string to put in the label
        pack_side - side to pack into the frame. Defaults to left.

        Description:
        Add a Label to the Frame
        '''
        frame = self.addFrame(pack_side, fill, expand)
        label = frame.addLabel(text)
        entry = frame.addEntry('right', **kwargs)
        return entry

    def addListboxWithScrollbar(self, pack_side='left', fill='both', expand=True, **kwargs):
        '''
        Arguments:
        kwargs - for the construction of the listbox

        Description:
        Add a Listbox with scrollbar to the Frame
        '''
        listbox = self.addListbox(**kwargs)
        scroller = self.addScrollbar(orient='vertical', borderwidth=1, command=listbox.yview)
        listbox.configure(yscrollcommand=scroller.set)
        return listbox
    
    def addTextboxWithScrollbar(self, pack_side='left', fill='both', expand=True, **kwargs):
        '''
        Arguments:
        kwargs - for the construction of the textbox

        Description:
        Add a textbox with scrollbar to the Frame
        '''
        textbox = self.addTextbox(**kwargs)
        scroller = self.addScrollbar(orient='vertical', borderwidth=1, command=textbox.changeView)
        textbox.configure(yscrollcommand=textbox.datayscroll)
        textbox.scroller = scroller
        return textbox

class Textbox(Text):
    def __init__(self, parent, data_model=None, key=None, context_manager=None, tcl_buffer_size=100, tcl_buffer_low_cutoff=0.25,
                 tcl_buffer_high_cutoff=0.75, tcl_moveto_yview=0.50, max_lines_jump=10, **kwargs):
        Text.__init__(self, parent, **kwargs)
        self.scroller = None
        self.context_manager = context_manager
        self.TCL_BUFFER_SIZE = tcl_buffer_size
        self.TCL_BUFFER_LOW_CUTOFF = tcl_buffer_low_cutoff
        self.TCL_BUFFER_HIGH_CUTOFF = tcl_buffer_high_cutoff
        self.TCL_MOVETO_YVIEW = tcl_moveto_yview
        self.MAX_LINES_JUMP = max_lines_jump
        self.reset()
        self.data_model = data_model
        self.key = key
        self.setCursor(START)
        # self.config(state=DISABLED)

    def reset(self):
        self.current_data_offset = 0
        self.prev_start = 0.0
        self.append_lines = 0
        self.prepend_lines = 0
        self.neg_to_pos = False
        self.paging_scroll_start = 0

    def setDataModel(self, data_model, key=None, progress_bar=None):
        self.reset()
        self.data_model = data_model
        self.key = key
        self.redraw()
        if progress_bar:
            self.context_manager.addCallback(progress_bar.stop)

    def appendData(self, data, moveto_end=False):
        self.data_model.append(data, key=self.key)
        self.insertBottomLine(self.data_model.getitem(-1, key=self.key))
        if moveto_end:
            if self.context_manager:
                self.context_manager.yview_moveto('1.0')
            else:
                self.yview_moveto('1.0')

    def clear(self):
        self.delete(0.0, END)
        if self.context_manager:
            self.context_manager.clearQueue()

    def redraw(self):
        num_lines = self.TCL_BUFFER_SIZE
        end_index = self.current_data_offset + num_lines
        if end_index > self.data_model.length(key=self.key):
            end_index = self.data_model.length(key=self.key)
            self.current_data_offset = end_index - num_lines
            if self.current_data_offset < 0:
                self.current_data_offset = 0
        start_index = self.current_data_offset
        
        self.clear()
        self.drawLines(start_index, end_index)

    def drawLines(self, start_index, end_index):
        for line in self.data_model.get(start_index, end_index, key=self.key):
            self.insertBottomLine(line)

    def redrawLine(self, index):
        self.delete(index, index + ' lineend')
        start = self.current_data_offset + int(index.split('.')[0]) - 1
        line = self.data_model.get(start, start+1, key=self.key).next().rstrip()
        self.context_manager.insert(index + ' lineend', line)

    def insertTopLine(self, line):
        if self.context_manager:
            self.context_manager.insert(START, line)
        else:
            self.insert(START, line)

    def insertBottomLine(self, line):
        if self.context_manager:
            self.context_manager.insert('end', line)
        else:
            self.insert('end', line)

    def deleteBottomLine(self):
        if self.context_manager:
            self.context_manager.addCallback(self._deleteBottomLine)
        else:
            self._deleteBottomLine()

    def _deleteBottomLine(self):
        lines_to_delete = int(float(self.index('end')) - self.TCL_BUFFER_SIZE) + 2
        self.delete('end -%i line linestart' % lines_to_delete, 'end lineend')

    def deleteTopLine(self):
        if self.context_manager:
            self.context_manager.addCallback(self._deleteTopLine)
        else:
            self._deleteTopLine()

    def _deleteTopLine(self):
        lines_to_delete = int(float(self.index('end')) - self.TCL_BUFFER_SIZE) - 2
        self.delete(START + ' linestart', START + ' linestart +%i line' % lines_to_delete)

    def datayscroll(self, *args):
        start = float(args[0])
        if abs(start - self.prev_start) > float(self.MAX_LINES_JUMP)/self.TCL_BUFFER_SIZE: # Debounce the noise
            self.prev_start = start
            return

        if self.data_model and self.data_model.length(key=self.key):
            if start > self.TCL_BUFFER_HIGH_CUTOFF and self.prev_start <= self.TCL_BUFFER_HIGH_CUTOFF:
                self.append_lines = 1
            elif start < self.TCL_BUFFER_LOW_CUTOFF and self.prev_start >= self.TCL_BUFFER_LOW_CUTOFF:
                self.append_lines = -1
                self.neg_to_pos = True             
            self.prev_start = start

            lines_to_update = self.TCL_BUFFER_SIZE/4
            if self.append_lines == 1:
                end = self.current_data_offset + self.TCL_BUFFER_SIZE
                if end < self.data_model.length(key=self.key):
                    if self.neg_to_pos: # for some reason, when we are deleting bottom lines, the trailing \n gets lost
                        self.insert('end', '\n')
                        self.neg_to_pos = False
                    for line in self.data_model.get(end, end + lines_to_update, key=self.key):
                        self.insertBottomLine(line)
                    self.deleteTopLine()
                    self.current_data_offset += lines_to_update
                    self.append_lines = 0
            elif self.append_lines == -1:
                if self.current_data_offset > 0:
                    last_index = max(self.current_data_offset - lines_to_update - 1, -1)
                    for line in self.data_model.get(self.current_data_offset - 1, last_index, -1, key=self.key):
                        self.insertTopLine(line)
                    self.deleteBottomLine()
                    self.current_data_offset -= lines_to_update
                    self.append_lines = 0

            start,end = self._calcscroller()
            self.scroller.set(start,end)
        else:
            self.scroller.set(*args)

    def _calcscroller(self):
        line_height = 1.0 / self.data_model.length(key=self.key)
        display_lines = line_height * self.cget('height')
        start = self.prev_start * self.TCL_BUFFER_SIZE / self.data_model.length(key=self.key) + self.current_data_offset * line_height
        end = start + display_lines
        return str(start),str(end)

    def setCursor(self, index):
        self.mark_set("insert", index)

    def changeView(self, *args):
        line_height = (1.0 / self.data_model.length(key=self.key))
        display_height = self.cget('height')
        if args[0] == 'moveto':
            new_loc = float(args[1])
            self.append_lines = 0
            self.current_data_offset = int(new_loc/line_height)-self.TCL_BUFFER_SIZE/2
            
            if self.current_data_offset < 0:
                view_start = self.TCL_MOVETO_YVIEW - float(-self.current_data_offset)/self.TCL_BUFFER_SIZE
                self.current_data_offset = 0 # TODO: analyze how well this one-line fix actually works
            elif self.current_data_offset + self.TCL_BUFFER_SIZE >= self.data_model.length(key=self.key):
                view_start = self.TCL_MOVETO_YVIEW + float(self.current_data_offset + self.TCL_BUFFER_SIZE - self.data_model.length(key=self.key))/self.TCL_BUFFER_SIZE
            else:
                view_start = self.TCL_MOVETO_YVIEW

            self.redraw() # insert all data

            new_end = new_loc + line_height * display_height
            self.scroller.set(new_loc, new_end)
            self.prev_start = new_loc
            
            if self.context_manager:
                self.context_manager.yview_moveto(view_start)
            else:
                self.yview_moveto(view_start)
        elif args[0] == 'scroll':
            num_pages = int(args[1])
            self.current_data_offset += num_pages * display_height

            if self.current_data_offset < 0:
                view_start = self.TCL_MOVETO_YVIEW - float(-self.current_data_offset)/self.TCL_BUFFER_SIZE
            elif self.current_data_offset + self.TCL_BUFFER_SIZE >= self.data_model.length(key=self.key):
                view_start = self.TCL_MOVETO_YVIEW + float(self.current_data_offset + self.TCL_BUFFER_SIZE - self.data_model.length(key=self.key))/self.TCL_BUFFER_SIZE
            else:
                view_start = self.TCL_MOVETO_YVIEW
            
            self.redraw()

            if self.current_data_offset == self.data_model.length(self.key) - self.TCL_BUFFER_SIZE:
                self.paging_scroll_start += display_height
            else:
                self.paging_scroll_start = self.current_data_offset

            new_start = float(self.paging_scroll_start) / (self.data_model.length(key=self.key) - self.TCL_BUFFER_SIZE)
            new_end = new_start + line_height * display_height
            self.scroller.set(new_start, new_end)
            self.prev_start = new_start
            
            if self.context_manager:
                self.context_manager.yview_moveto(view_start)
            else:
                self.yview_moveto(view_start)
        else:
            print args

class ContextMenu(Menu):
    def __init__(self, label_command_pairs):
        Menu.__init__(self, tearoff=0)
        self.context = None
        for label, callback in label_command_pairs:
            self.add_command(label=label, command=lambda: callback(self.context))

class Location():
    def __init__(self, index, textbox):
        self.index = index
        self.textbox = textbox
