'''
Author: Joshua Christman

This file contains many classes to make the code in the main interface much more readable.
It also adds many convenience functions to code to make access easier.
'''

from Tkinter import Menu, Button, Label, Text, Listbox, Scrollbar, Entry, PanedWindow as pw, Frame as fm, INSERT, END
from ttk import Progressbar, Notebook as nb

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
        kwargs - keyword arguments for the listbox

        Description:
        Add a listbox with a label for the notebook
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
        scroller = self.addScrollbar(orient='vertical', borderwidth=1, command=textbox.yview)
        textbox.configure(yscrollcommand=scroller.set)
        return textbox

class Textbox(Text):
    def __init__(self, parent, **kwargs):
        Text.__init__(self, parent, **kwargs)

    def setData(self, data):
        self.delete(0.0, END) # Get rid of current data
        self.insert(INSERT, data)

    def appendData(self, data):
        self.insert(INSERT, data)
