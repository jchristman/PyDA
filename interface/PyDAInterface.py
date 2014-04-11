from Tkinter import Tk, Frame, Menu, Text, Scrollbar, Button, BOTH, END
import tkFileDialog, tkMessageBox
from disassembler.formats.helpers import CommonProgramDisassemblyFormat

def build_and_run(disassembler):
    root = Tk()
    app = PyDAInterface(root, disassembler)
    root.mainloop()

class PyDAInterface(Frame):
    def __init__(self, parent, disassembler):
        Frame.__init__(self, parent)
        self.parent = parent
        self.disassembler = disassembler
        self.initUI()
        self.centerWindow()
        self.focus_force()

    def initUI(self):
        self.parent.title("PyDA")

        ## Set up the menu bar ##
        self.menubar = Menu(self.parent)
        self.parent.config(menu=self.menubar)

        self.fileMenu = Menu(self.menubar, tearoff=0)
        self.fileMenu.add_command(label="Import", command=self.import_file)
        self.fileMenu.add_separator()
        self.fileMenu.add_command(label="Exit", command=self.onExit)

        self.menubar.add_cascade(label="File", menu=self.fileMenu)
        #########################

        ## Create the PyDA toolbar ##
        self.toolbar = Frame()
        
        self.import_button = Button(text="Import", borderwidth=1, command=self.import_file)
        self.import_button.pack(in_=self.toolbar, side="left")
        #############################

        ## Set up the main PyDA Disassembly Window ##
        self.mainFrame = Frame(borderwidth=1, relief="sunken")
        self.disassembly_text_widget = Text(background="white", borderwidth=0, highlightthickness=0)
        self.scroller = Scrollbar(orient="vertical", borderwidth=1, command=self.disassembly_text_widget.yview)
        self.disassembly_text_widget.configure(yscrollcommand=self.scroller.set)
        self.scroller.pack(in_=self.mainFrame, side="right", fill="y", expand=False)
        self.disassembly_text_widget.pack(in_=self.mainFrame, side="left", fill="both", expand=True)
        #############################################

        ## Now pack things in the correct order ##
        self.toolbar.pack(side="top", fill="x")
        self.mainFrame.pack(side="bottom", fill="both", expand=True)
        ##########################################

        self.parent.bind("<Button-3>", self.contextMenu)

    def centerWindow(self):
        height = self.parent.winfo_screenheight()*3/4
        width = height * 16 / 9
        x = (self.parent.winfo_screenwidth() - width)/2
        y = (self.parent.winfo_screenheight() - height)/2
        self.parent.geometry('%dx%d+%d+%d' % (width, height, x, y))

    def contextMenu(self, e):
        print vars(e)

    def onError(self):
        tkMessageBox.showerror("Error", "Could not determine file type from magic header.")

    def onExit(self):
        self.quit()

    ########### PyDA Specific Functions ###########
    def import_file(self):
        # Returns the opened file
        dialog = tkFileDialog.Open(self)
        file = dialog.show()
        
        if not file == '':
            binary = open(file, 'rb').read()

            self.disassembler.load(binary)

            disassembly = self.disassembler.disassemble()
            if isinstance(disassembly, CommonProgramDisassemblyFormat):
                # Set current text to file contents
                self.disassembly_text_widget.delete(0.0, END)
                self.disassembly_text_widget.insert(0.0, disassembly.toString())

if __name__ == '__main__':
    build_and_run()
