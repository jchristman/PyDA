from Tkinter import CURRENT

class FunctionNameManager:

    def __init__(self, text):
        self.text = text # This is the Tkinter text object that we want to add special stuff to
        self.text.tag_config("function", foreground="blue")
        self.text.tag_bind("function", "<Button-3>", self.right_click)
        self.reset()

    def reset(self):
        self.functions = {}

    def add(self, action):
        tag = "function-%i" % len(self.functions)
        self.functions[tag] = action
        return "function", tag

    def right_click(self, event):
        for tag in self.text.tag_names(CURRENT):
            if tag[:9] == "function-":
                self.functions[tag](tag)
                return
