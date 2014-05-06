import Tkinter as tki # Tkinter -> tkinter in Python 3

class GUI(tki.Tk):
    def __init__(self):
        tki.Tk.__init__(self)

        # create a popup menu
        self.aMenu = tki.Menu(self, tearoff=0)
        self.aMenu.add_command(label="Undo", command=self.hello)
        self.aMenu.add_command(label="Redo", command=self.hello)

        # create a frame
        self.aFrame = tki.Frame(self, width=512, height=512)
        self.aFrame.pack()

        # attach popup to frame
        self.aFrame.bind("<Button-3>", self.popup)

    def hello(self):
        print "hello!"

    def popup(self, event):
        self.aMenu.post(event.x_root, event.y_root)

gui = GUI()
gui.mainloop()
