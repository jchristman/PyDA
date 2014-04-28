'''
Author: Joshua Christman

This file contains many classes to make the code in the main interface much more readable.
It also adds many convenience functions to code to make access easier.
'''

from Tkinter import Menu, Frame

class MenuBar(Menu):
    '''
    A custom subclass of Menu that allows easy customization of a menu bar in a Tkinter App
    '''
    def __init__(self, parent):
        Menu.__init__(self, parent)
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
    A container class that provide convenience functions for a toolbar.
    '''
    def __init__(self, parent, pack_options):
        Frame.__init__(self, parent)
        

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
    root.mainloop()
