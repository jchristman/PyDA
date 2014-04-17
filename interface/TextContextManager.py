from Tkinter import CURRENT
from tkFont import Font
from platform import system

class TextContextManager:

    def __init__(self, text):
        self.text = text # This is the Tkinter text object that we want to add special stuff to
        
        button = "<Button-2>" if system() == "Darwin" else "<Button-3>"
        
        self.bold_font = Font(weight="bold")

        self.text.tag_config("function", foreground="blue")
        self.text.tag_bind("function", button, self.right_click)
        self.text.tag_config("address", foreground="darkblue")
        self.text.tag_bind("address", button, self.right_click)
        self.text.tag_config("section", foreground="darkgreen", font=self.bold_font)
        self.text.tag_bind("section", button, self.right_click)
        self.text.tag_config("comment", foreground="darkgreen")
        self.text.tag_bind("comment", button, self.right_click)

        self.reset()

    def reset(self):
        self.functions = {}
        self.addresses = {}
        self.comments  = {}
        self.sections  = {}
        self.reverse_tag_lookup = {'function' : self.functions, 'address' : self.addresses, 'comment' : self.comments, 'section' : self.sections}

    def add(self, action, tag_prefix):
        tag = "%s-%i" % (tag_prefix, len(self.reverse_tag_lookup[tag_prefix]))
        self.reverse_tag_lookup[tag_prefix][tag] = action
        return tag_prefix, tag

    def addComment(self, action):
        return self.add(action, 'comment')
        
    def addSection(self, action):
        return self.add(action, 'section')
    
    def addAddress(self, action):
        return self.add(action, 'address')

    def addFunction(self, action):
        return self.add(action, 'function')

    def right_click(self, event):
        for tag in self.text.tag_names(CURRENT)[1:]:
            tag_prefix = tag.split('-')[0]
            self.reverse_tag_lookup[tag_prefix][tag](tag)
            return
