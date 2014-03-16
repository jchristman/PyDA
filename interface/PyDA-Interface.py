from Tkinter import Tk, BOTH
from ttk import Frame, Button, Style

class PyDAInterface(Frame):
    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.parent = parent
        self.initUI()
        self.centerWindow()

    def initUI(self):
        self.parent.title("PyDA")

        self.style = Style()
        self.style.theme_use("default")
        
        self.pack(fill=BOTH, expand=1)

    def centerWindow(self):
        height = self.parent.winfo_screenheight()*3/4
        width = height * 16 / 9
        x = (self.parent.winfo_screenwidth() - width)/2
        y = (self.parent.winfo_screenheight() - height)/2
        self.parent.geometry('%dx%d+%d+%d' % (width, height, x, y))


if __name__ == '__main__':
    root = Tk()
    app = PyDAInterface(root)
    root.mainloop()
