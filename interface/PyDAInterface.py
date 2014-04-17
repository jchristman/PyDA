from Tkinter import Tk, PanedWindow, Frame, Label, Menu, Text, Entry, Scrollbar, Listbox, Button, BOTH, END, INSERT
from disassembler.formats.helpers import CommonProgramDisassemblyFormat
from ttk import Notebook
from TextContextManager import TextContextManager
import tkFileDialog, tkMessageBox

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
        self.import_button = Button(self.toolbar, text="Import", borderwidth=1, command=self.import_file)
        self.import_button.pack(side="left")
        #############################

        self.top_level_window = PanedWindow(borderwidth=1, relief="sunken", sashwidth=4, orient="vertical")
        self.main_window = PanedWindow(self.top_level_window, borderwidth=1, relief="sunken", sashwidth=4)

        self.right_notebook = Notebook(self.main_window)
        self.left_notebook = Notebook(self.main_window)
        
        ## Set up the main PyDA Disassembly Window ##
        self.disassembly_frame = Frame(self.right_notebook)
        self.disassembly_text_widget = Text(self.disassembly_frame, background="white", borderwidth=1, highlightthickness=1)
        self.dis_text_scroller = Scrollbar(self.disassembly_frame, orient="vertical", borderwidth=1, command=self.disassembly_text_widget.yview)
        self.disassembly_text_widget.configure(yscrollcommand=self.dis_text_scroller.set)
        self.dis_text_scroller.pack(side="right", fill="y", expand=False)
        self.disassembly_text_widget.pack(side="left", fill="both", expand=True)
        self.right_notebook.add(self.disassembly_frame, text="Disassembled Code")
        #############################################

        ## Set up the Data Section Frame ##
        self.data_section_frame = Frame(self.right_notebook)
        self.data_section_text_widget = Text(self.data_section_frame, background="white", borderwidth=1, highlightthickness=1)
        self.data_sec_text_scroller = Scrollbar(self.data_section_frame, orient="vertical", borderwidth=1, command=self.data_section_text_widget.yview)
        self.data_section_text_widget.configure(yscrollcommand=self.data_sec_text_scroller.set)
        self.data_sec_text_scroller.pack(side="right", fill="y", expand=False)
        self.data_section_text_widget.pack(side="left", fill="both", expand=True)
        self.right_notebook.add(self.data_section_frame, text="Data Sections")
        #############################################

        ## Functions Side Bar ##
        self.functions_frame = Frame(self.left_notebook)
        self.functions_listbox = Listbox(self.functions_frame, background="white", borderwidth=1, highlightthickness=1)
        self.functions_scroller = Scrollbar(self.functions_frame, orient="vertical", borderwidth=1, command=self.functions_listbox.yview)
        self.functions_listbox.configure(yscrollcommand=self.functions_scroller.set)
        self.functions_scroller.pack(side="right", fill="y", expand=False)
        self.functions_listbox.pack(side="left", fill="both", expand=True)
        self.left_notebook.add(self.functions_frame, text="Functions")
        ########################

        ## String Side Bar ##
        self.strings_frame = Frame(self.left_notebook)
        self.strings_listbox = Listbox(self.strings_frame, background="white", borderwidth=1, highlightthickness=1)
        self.strings_scroller = Scrollbar(self.strings_frame, orient="vertical", borderwidth=1, command=self.strings_listbox.yview)
        self.strings_listbox.configure(yscrollcommand=self.strings_scroller.set)
        self.strings_scroller.pack(side="right", fill="y", expand=False)
        self.strings_listbox.pack(side="left", fill="both", expand=True)
        self.left_notebook.add(self.strings_frame, text="Strings")
        #####################

        ## Chat Window ##
        self.chat_frame = Frame(self.top_level_window, borderwidth=1, relief="sunken")
        self.chat_recv_frame = Frame(self.chat_frame)
        self.chat_text_widget = Text(self.chat_recv_frame, background="white", borderwidth=1, highlightthickness=1)
        self.chat_text_scroller = Scrollbar(self.chat_recv_frame, orient="vertical", borderwidth=1, command=self.chat_text_widget.yview)
        self.chat_text_widget.configure(yscrollcommand=self.chat_text_scroller.set)
        self.chat_text_scroller.pack(side="right", fill="y", expand=False)
        self.chat_text_widget.pack(side="left", fill="both", expand=True)
        self.chat_send_text = Entry(self.chat_frame, background="white", borderwidth=2, highlightthickness=1)
        self.chat_send_text.pack(side="bottom", fill="x", expand=False)
        self.chat_recv_frame.pack(side="top", fill="both", expand=True)
        #################

        ## Now pack things in the correct order ##
        self.main_window.add(self.left_notebook)
        self.main_window.add(self.right_notebook)
        self.top_level_window.add(self.main_window)
        self.top_level_window.add(self.chat_frame)
        self.toolbar.pack(side="top", fill="x")
        self.top_level_window.pack(side="top", fill="both", expand=True)
        ##########################################

        self.text_context_manager = TextContextManager(self.disassembly_text_widget)
        self.disassembly_text_widget.insert(INSERT, ".text", self.text_context_manager.addSection(self.text_context_right_click))
        self.disassembly_text_widget.insert(INSERT, " ")
        self.disassembly_text_widget.insert(INSERT, "0x0804C040", self.text_context_manager.addAddress(self.text_context_right_click))
        self.disassembly_text_widget.insert(INSERT, " call ")
        self.disassembly_text_widget.insert(INSERT, "func_0", self.text_context_manager.addFunction(self.text_context_right_click))
        self.disassembly_text_widget.insert(INSERT, "   ")
        self.disassembly_text_widget.insert(INSERT, "-- This is a test comment", self.text_context_manager.addComment(self.text_context_right_click))

    def centerWindow(self):
        height = self.parent.winfo_screenheight()*3/4
        width = height * 16 / 9
        x = (self.parent.winfo_screenwidth() - width)/2
        y = (self.parent.winfo_screenheight() - height)/2
        self.parent.geometry('%dx%d+%d+%d' % (width, height, x, y))

    def text_context_right_click(self, text_tag):
        print 'Right clicked %s!' % text_tag

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
                for function in disassembly.functions:
                    self.functions_listbox.insert(END, function.name)
                
                self.disassembly_text_widget.delete(0.0, END)
                self.disassembly_text_widget.insert(0.0, disassembly.toString())

if __name__ == '__main__':
    build_and_run()
