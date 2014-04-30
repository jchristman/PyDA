'''
Author: Joshua Christman

This file contains many classes to make the code in the main interface much more readable.
It also adds many convenience functions to code to make access easier.
'''

from Tkinter import Menu, Button, Label, Text, Listbox, Scrollbar, Entry, PanedWindow as pw, Frame as fm, INSERT, END
from ttk import Progressbar, Notebook as nb
from settings import LINES_BUFFER_SIZE, LINES_BUFFER_LOW_CUTOFF, LINES_BUFFER_HIGH_CUTOFF, START, MOVETO_YVIEW, MAX_JUMP_CUTOFF

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
    def __init__(self, parent, context_manager=None, **kwargs):
        Text.__init__(self, parent, **kwargs)
        self.scroller = None
        self.context_manager = context_manager
        self.reset()

    def reset(self):
        self.data = [] # It's an array of lines
        self.current_data_offset = 0
        self.prev_start = 0.0
        self.append_lines = 0
        self.prepend_lines = 0
        self.neg_to_pos = False
        self.paging_scroll_start = 0

    def setData(self, data):
        self.reset()
        self.data = [x + '\n' for x in data.split('\n') if len(x) > 0]
        self.redraw()

    def appendData(self, data):
        self.data.append(data)
        self.redraw()

    def clear(self):
        self.delete(0.0, END)

    def redraw(self):
        num_lines = LINES_BUFFER_SIZE
        end_index = self.current_data_offset + num_lines
        if end_index > len(self.data):
            end_index = len(self.data)
            self.current_data_offset = end_index - num_lines
            if self.current_data_offset < 0:
                self.current_data_offset = 0
        start_index = self.current_data_offset

        self.clear()
        self.drawLines()

    def drawLines(self):
        for i in xrange(LINES_BUFFER_SIZE):
            self.insertBottomLine(self.current_data_offset + i)

    def insertTopLine(self, line_index):
        if 0 <= line_index < len(self.data):
            if self.context_manager:
                self.context_manager.insert(self, START, self.data[line_index])
            else:
                self.insert(START, self.data[line_index])

    def insertBottomLine(self, line_index):
        if 0 <= line_index < len(self.data):
            if self.context_manager:
                self.context_manager.insert(self, 'end', self.data[line_index])
            else:
                self.insert('end', self.data[line_index])

    def deleteBottomLine(self):
        lines_to_delete = int(float(self.index('end')) - LINES_BUFFER_SIZE) + 2
        self.delete('end -%i line linestart' % lines_to_delete, 'end lineend')

    def deleteTopLine(self):
        lines_to_delete = int(float(self.index('end')) - LINES_BUFFER_SIZE)
        self.delete(START + ' linestart', START + ' linestart +%i line' % lines_to_delete)

    def datayscroll(self, *args):
        if args[0] == 'BYPASS':
            self.prev_start = float(args[1])
            self.scroller.set(args[1], args[2])
            return

        start = float(args[0])
        if abs(start - self.prev_start) > MAX_JUMP_CUTOFF: # Then we are getting residual effects of changing the buffer with the scrollbar
            return # ignore the residual effect

        if len(self.data) > 0:
            if start > LINES_BUFFER_HIGH_CUTOFF and self.prev_start <= LINES_BUFFER_HIGH_CUTOFF: # Then we add lines to end and delete lines from front
                self.append_lines = 1
            elif start <= LINES_BUFFER_HIGH_CUTOFF and self.prev_start > LINES_BUFFER_HIGH_CUTOFF: # Then we are back in the neutral zone
                self.append_lines = 0
            elif start < LINES_BUFFER_LOW_CUTOFF and self.prev_start >= LINES_BUFFER_LOW_CUTOFF: # Then we add lines to front and delete lines from end
                self.append_lines = -1
                self.neg_to_pos = True
            elif start >= LINES_BUFFER_LOW_CUTOFF and self.prev_start < LINES_BUFFER_LOW_CUTOFF: # Then we are back in the neutral zone
                self.append_lines = 0                
            self.prev_start = start

            if self.append_lines == 1:
                lines_to_update = abs(int((self.prev_start - LINES_BUFFER_HIGH_CUTOFF)/(1.0/LINES_BUFFER_SIZE)))
                if self.current_data_offset + LINES_BUFFER_SIZE < len(self.data):
                    if self.neg_to_pos: # for some reason, when we are deleting bottom lines, the trailing \n gets lost
                        self.insert('end', '\n')
                        self.neg_to_pos = False
                    for i in xrange(lines_to_update):
                        self.insertBottomLine(self.current_data_offset + LINES_BUFFER_SIZE + i)
                        self.deleteTopLine()
                    self.current_data_offset += lines_to_update
            elif self.append_lines == -1:
                lines_to_update = abs(int((self.prev_start - LINES_BUFFER_LOW_CUTOFF)/(1.0/LINES_BUFFER_SIZE)))
                if self.current_data_offset > 0:
                    for i in xrange(lines_to_update):
                        self.deleteBottomLine()
                        self.insertTopLine(self.current_data_offset - 1 - i)
                    self.current_data_offset -= lines_to_update

            start,end = self._calcscroller()
            self.scroller.set(start,end)
        else:
            self.scroller.set(*args)

    def _calcscroller(self):
        line_height = 1.0 / len(self.data)
        display_lines = line_height * self.cget('height')
        start = self.prev_start * LINES_BUFFER_SIZE / len(self.data) + self.current_data_offset * line_height
        end = start + display_lines
        return str(start),str(end)

    def changeView(self, *args):
        line_height = (1.0 / len(self.data))
        display_height = self.cget('height')
        if args[0] == 'moveto':
            new_start = float(args[1])
            self.append_lines = 0 # Stop inserting or deleting lines
            self.current_data_offset = int(new_start/line_height) # divide the start location by the height of the line and truncate to an int
            self.redraw() # insert all data
            
            # Now to a calculation for the position of the cursor
            end = new_start + line_height * display_height
            self.datayscroll('BYPASS', new_start, end)
            
            view_test_start = float(self.current_data_offset) / LINES_BUFFER_SIZE
            view_test_end = len(self.data) - int(new_start/line_height)
            # We are going to set our position within the tcl buffer to some percentage of where we are in the file.
            if view_test_start < MOVETO_YVIEW:
                view_start = str(view_test_start)
            else:
                view_start = str(float(LINES_BUFFER_SIZE - view_test_end) / LINES_BUFFER_SIZE)
            self.yview_moveto(view_start)
        elif args[0] == 'scroll':
            num_pages = int(args[1])
            self.current_data_offset += num_pages * display_height
            self.redraw()

            if self.current_data_offset == len(self.data) - LINES_BUFFER_SIZE:
                self.paging_scroll_start += display_height
            else:
                self.paging_scroll_start = self.current_data_offset

            new_start = float(self.paging_scroll_start) / (len(self.data) - LINES_BUFFER_SIZE)
            end = new_start + line_height * display_height
            self.datayscroll('BYPASS', new_start, end)
            
            view_test_start = float(self.current_data_offset) / LINES_BUFFER_SIZE
            view_test_end = len(self.data) - int(self.paging_scroll_start/line_height)
            if view_test_start < MOVETO_YVIEW:
                view_start = str(view_test_start)
            else:
                view_start = str(float(LINES_BUFFER_SIZE - view_test_end) / LINES_BUFFER_SIZE)
            self.yview_moveto(view_start)
        else:
            print args
