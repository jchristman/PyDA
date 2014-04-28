'''
Author: Joshua Christman

This file contains many classes to make the code in the main interface much more readable.
It also adds many convenience functions to code to make access easier.
'''

from Tkinter import Menu, Frame, Button, Label, Text
from Tkinter import PanedWindow as pw # because I like the term PanedWindow and I want to use it
from ttk import Notebook as nb # because I like the term Notebook and I want to use it
from ttk import Progressbar

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

class ToolBar(Frame):
    '''
    Arguments:
    parent - the Tkinter master
    pack_location - location of the tool bar within the master
    kwargs - optional keyword arguments ot be passed to the Frame superclass

    Description:
    A container class that provide convenience functions for a toolbar.
    '''
    def __init__(self, parent, pack_location, **kwargs):
        Frame.__init__(self, parent, **kwargs)
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
        return uuid
        
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
        return uuid

    def addPanedWindow(self, **kwargs):
        '''
        Arguments:
        pack_location - where to pack the paned window
        kwargs - keyword arguments to be passwed to constructor

        Description:
        Adds a paned window to the paned window
        '''
        return self.addElement(PanedWindow(self, **kwargs))

    def addNotebook(self, pack_location, **kwargs):
        '''
        Arguments:
        pack_location - where to pack the paned window
        kwargs - keyword arguments to be passwed to constructor

        Description:
        Adds a notebook to the paned window
        '''
        return self.addElement(Notebook(self, pack_location, **kwargs))

class Notebook(nb):
    '''
    Arguments:
    parent - the Tkinter master widget
    pack_location - where to pack the notebook

    Description:
    A subclass of the ttk notebook
    '''
    def __init__(self, parent, pack_location=None, **kwargs):
        nb.__init__(self, parent, **kwargs)
        self.elements = {}
        if pack_location:
            self.pack(side=pack_location)

    def addElement(self, element):
        '''
        Arguments:
        element - a tkinter widget

        Description:
        Add the element to the PanedWindow
        '''
        uuid = len(self.elements)
        self.elements[uuid] = element
        self.add(element)
        return uuid

if __name__ == '__main__':
    from Tkinter import Tk, Frame
    def testFunc():
        print 'Test!'
        
    root = Tk()

    main = Frame(root)
    main.pack()

    menu = MenuBar(root)
    menu.addMenu('File')
    menu.addMenuItem('File', 'Import', testFunc)
    menu.addMenuSeparator('File')
    menu.addMenuItem('File', 'Exit', exit)
    menu.addMenu('Settings')
    menu.addMenuItem('Settings', 'Edit', testFunc)

    tool_bar = ToolBar(root, 'top')
    tool_bar.addButton('Test', testFunc, 'left')
    tool_bar.addButton('Test2', testFunc, 'right')

    status_bar = ToolBar(root, 'bottom', borderwidth=2, relief='sunken')
    status_bar.addLabel('Test3', 'left')
    bar_uuid = status_bar.addProgressBar('right', length=200, mode='indeterminate')

    tl_window = PanedWindow(root, 'top', borderwidth=1, relief='sunken', sashwidth=4, orient='vertical')
    tl_h_window = PanedWindow(tl_window, None, borderwidth=1, relief='sunken', sashwidth=4)
    #tl_h_window.addNotebook(

    root.geometry('%dx%d+%d+%d' % (300, 300, 100, 100))

    root.mainloop()
