from Tkinter import CURRENT
from tkFont import Font
from platform import system

class TextContextManager:

    def __init__(self, text):
        self.text = text # This is the Tkinter text object that we want to add special stuff to
        
        button = "<Button-2>" if system() == "Darwin" else "<Button-3>"
        
        self.bold_font = Font(weight="bold")


        self.text.tag_config("section", foreground="darkgreen")
        self.text.tag_bind("section", button, self.right_click)
        self.text.tag_config("address", foreground="darkorange")
        self.text.tag_bind("address", button, self.right_click)
        self.text.tag_config("mnemonic", foreground="blue")
        self.text.tag_bind("mnemonic", button, self.right_click)
        self.text.tag_config("op_str", foreground="blue")
        self.text.tag_bind("op_str", button, self.right_click)
        self.text.tag_config("comment", foreground="darkgreen")
        self.text.tag_bind("comment", button, self.right_click)

        self.reset()

    def reset(self):
        self.sections  = {}
        self.addresses = {}
        self.mnemonics = {}
        self.op_strs = {}
        self.comments  = {}
        self.reverse_tag_lookup = {'op_str' : self.op_strs, 'address' : self.addresses, 'comment' : self.comments, 'section' : self.sections, 'mnemonic' : self.mnemonics}

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

    def addOpStr(self, action):
        return self.add(action, 'op_str')

    def right_click(self, event):
        for tag in self.text.tag_names(CURRENT)[1:]:
            tag_prefix = tag.split('-')[0]
            self.reverse_tag_lookup[tag_prefix][tag](tag)
            return
