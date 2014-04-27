from Tkinter import Tk, PanedWindow, Frame, Label, Menu, Text, Entry, Scrollbar, Listbox, Button, IntVar, BOTH, END, INSERT, LEFT
from ttk import Notebook,Progressbar
from disassembler.formats.helpers import CommonProgramDisassemblyFormat
from WidgetClickContextManager import WidgetClickContextManager
from StdoutRedirector import StdoutRedirector
from platform import system
from Queue import Queue
from thread import start_new_thread
import sys
import tkFileDialog, tkMessageBox

def build_and_run(disassembler, server):
    rootApp = RootApplication()
    app = PyDAInterface(rootApp, disassembler, server)
    rootApp.mainloop()

class RootApplication(Tk):
    def __init__(self):
        Tk.__init__(self)
        self.callback_queue = Queue()
        self.progress_monitor = False
        self.progress_point_callback = None
        self.total_points = 0
        self.pollCallbackQueue()

    def startProgressMonitor(self, callback):
        self.progress_monitor = True
        self.progress_point_callback = callback

    def stopProgressMonitor(self):
        self.progress_monitor = False

    def addCallback(self, callback, args=None):
        self.callback_queue.put((callback, args))

    def addProgressPoint(self):
        self.addCallback('PROGRESS POINT')

    def pollCallbackQueue(self):
        pollProcessSize = 500
        progress_points = 0

        for i in xrange(pollProcessSize):
            if self.callback_queue.empty():
                break

            callback,args = self.callback_queue.get()
            if callback == 'PROGRESS POINT':
                progress_points += 1
            elif args:
                callback(*args)
            else:
                callback()

        self.total_points += progress_points

        if self.progress_monitor:
            self.progress_point_callback(progress_points)
        
        self.after(10, self.pollCallbackQueue)

class PyDAInterface(Frame):
    def __init__(self, parent, disassembler, server):
        Frame.__init__(self, parent)
        self.parent = parent
        self.disassembler = disassembler
        self.server = server
        self.initUI()
        self.centerWindow()

    def initUI(self):
        self.parent.title("PyDA")

        ## Set up the menu bar ##
        self.menubar = Menu(self.parent)
        self.parent.config(menu=self.menubar)

        self.fileMenu = Menu(self.menubar, tearoff=0)
        self.fileMenu.add_command(label="Import", command=self.importFile)
        self.fileMenu.add_separator()
        self.fileMenu.add_command(label="Exit", command=self.onExit)

        self.menubar.add_cascade(label="File", menu=self.fileMenu)
        #########################

        ## Create the PyDA toolbar ##
        self.toolbar = Frame()
        self.import_button = Button(self.toolbar, text="Import", borderwidth=1, command=self.importFile)
        self.import_button.pack(side="left")
        self.share_button = Button(self.toolbar, text="Share", borderwidth=1, command=self.share)
        self.share_button.pack(side="left")
        #############################
        
        ## Create the PyDA status bar ##
        self.status_bar = Frame(borderwidth=2)
        self.status_progress_bar = Progressbar(self.status_bar, length=200, mode='determinate')
        self.status_progress_bar['maximum'] = 100
        self.status_progress_bar['value'] = 0
        self.status_progress_bar.pack(side='right', padx=3)
        self.static_status_label = Label(self.status_bar, text='Status:')
        self.status_label = Label(self.status_bar, text='Ready')
        self.static_status_label.pack(side='left')
        self.status_label.pack(side='left', fill='x')
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
        self.dis_text_scroller.pack(side="right", fill="y")
        self.disassembly_text_widget.pack(side="left", fill="both", expand=True)
        self.right_notebook.add(self.disassembly_frame, text="Disassembled Code")
        #############################################

        ## Set up the Data Section Frame ##
        self.data_section_frame = Frame(self.right_notebook)
        self.data_section_text_widget = Text(self.data_section_frame, background="white", borderwidth=1, highlightthickness=1)
        self.data_sec_text_scroller = Scrollbar(self.data_section_frame, orient="vertical", borderwidth=1, command=self.data_section_text_widget.yview)
        self.data_section_text_widget.configure(yscrollcommand=self.data_sec_text_scroller.set)
        self.data_sec_text_scroller.pack(side="right", fill="y")
        self.data_section_text_widget.pack(side="left", fill="both", expand=True)
        self.right_notebook.add(self.data_section_frame, text="Data Sections")
        #############################################

        ## Functions Side Bar ##
        self.functions_frame = Frame(self.left_notebook)
        self.functions_listbox = Listbox(self.functions_frame, background="white", borderwidth=1, highlightthickness=1)
        self.functions_scroller = Scrollbar(self.functions_frame, orient="vertical", borderwidth=1, command=self.functions_listbox.yview)
        self.functions_listbox.configure(yscrollcommand=self.functions_scroller.set)
        self.functions_scroller.pack(side="right", fill="y")
        self.functions_listbox.pack(side="left", fill="both", expand=True)
        self.left_notebook.add(self.functions_frame, text="Functions")
        ########################

        ## String Side Bar ##
        self.strings_frame = Frame(self.left_notebook)
        self.strings_listbox = Listbox(self.strings_frame, background="white", borderwidth=1, highlightthickness=1)
        self.strings_scroller = Scrollbar(self.strings_frame, orient="vertical", borderwidth=1, command=self.strings_listbox.yview)
        self.strings_listbox.configure(yscrollcommand=self.strings_scroller.set)
        self.strings_scroller.pack(side="right", fill="y")
        self.strings_listbox.pack(side="left", fill="both", expand=True)
        self.left_notebook.add(self.strings_frame, text="Strings")
        #####################

        ## Chat Window ##
        self.chat_frame = Frame(self.top_level_window, borderwidth=1, relief="sunken")
        self.chat_recv_frame = Frame(self.chat_frame)
        self.chat_text_widget = Text(self.chat_recv_frame, background="white", borderwidth=1, highlightthickness=1)
        self.chat_text_scroller = Scrollbar(self.chat_recv_frame, orient="vertical", borderwidth=1, command=self.chat_text_widget.yview)
        self.chat_text_widget.configure(yscrollcommand=self.chat_text_scroller.set)
        self.chat_text_scroller.pack(side="right", fill="y")
        self.chat_text_widget.pack(side="left", fill="both", expand=True)
        self.chat_send_text = Entry(self.chat_frame, background="white", borderwidth=2, highlightthickness=1)
        self.chat_send_text.pack(side="bottom", fill="x")
        self.chat_recv_frame.pack(side="top", fill="both", expand=True)
        #################

        ## Now pack things in the correct order ##
        self.main_window.add(self.left_notebook)
        self.main_window.add(self.right_notebook)
        self.top_level_window.add(self.main_window)
        self.top_level_window.add(self.chat_frame)
        self.toolbar.pack(side="top", fill="x")
        self.status_bar.pack(side="bottom", fill="x")
        self.top_level_window.pack(side="top", fill="both", expand=True)
        ##########################################

        self.tk_focusFollowsMouse()

        right_click_button = "<Button-2>" if system() == "Darwin" else "<Button-3>"
        self.disassembly_text_context_manager = WidgetClickContextManager(self.disassembly_text_widget, right_click_button, 
                                                self.text_context_right_click, [('section','darkgreen'),('address','darkorange'),
                                                ('mnemonic','blue'),('op_str','blue'),('comment','darkgreen')])
        sys.stdout = StdoutRedirector(self.stdoutMessage)
        print "Stdout is being redirected to here"

    def centerWindow(self):
        height = self.parent.winfo_screenheight()*3/4
        width = height * 16 / 9
        x = (self.parent.winfo_screenwidth() - width)/2
        y = (self.parent.winfo_screenheight() - height)/2
        self.parent.geometry('%dx%d+%d+%d' % (width, height, x, y))

    def text_context_right_click(self, text_tag):
        print 'Right clicked %s' % text_tag

    def stdoutMessage(self, message):
        self.chat_text_widget.insert(INSERT, '%s' % message)
        self.chat_text_widget.yview_moveto(1)

    def contextMenu(self, e):
        print vars(e)

    def onError(self):
        tkMessageBox.showerror("Error", "Could not determine file type from magic header.")

    def onExit(self):
        self.quit()

    def progressMonitorCallback(self, step):
        orig = self.status_progress_bar['value']
        self.status_progress_bar.step(step)
        if self.status_progress_bar['value'] >= self.status_progress_bar['maximum'] or orig > self.status_progress_bar['value']:
            self.parent.stopProgressMonitor()
            self.status('Finished')

    def status(self, message):
        self.parent.addCallback(self._status, (message,))

    def _status(self, message):
        self.status_label['text'] = message

    ########### PyDA Specific Functions ###########
    def importFile(self):
        # Returns the opened file
        dialog = tkFileDialog.Open(self)
        file_name = dialog.show()
        start_new_thread(self.disassembleFile, (file_name,))

    def disassembleFile(self, file_name):
        if not file_name == '':
            binary = open(file_name, 'rb').read()

            self.status_progress_bar['mode'] = 'indeterminate'
            self.parent.addCallback(self.status_progress_bar.start)
            
            self.status('Loading %s' % file_name)
            self.disassembler.load(binary)
            self.status('Disassembling as %s' % self.disassembler.getFileType())
            disassembly = self.disassembler.disassemble()
            
            self.parent.addCallback(self.status_progress_bar.stop)
            
            if isinstance(disassembly, CommonProgramDisassemblyFormat):
                for function in disassembly.functions:
                    self.parent.addCallback(self.functions_listbox.insert, (END, function.name))

                self.parent.addCallback(self.disassembly_text_widget.delete, (0.0, END))
                self.dis_lines = disassembly.serialize()
                lines_to_process = len(self.dis_lines)
                
                self.current_section = ''
                self.current_function = ''
                self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, disassembly.program_info))

                self.status_progress_bar['mode'] = 'determinate'
                self.status_progress_bar['maximum'] = lines_to_process
                self.status_progress_bar['value'] = 0
                self.parent.startProgressMonitor(self.progressMonitorCallback)
 
                self.status('Processing lines')
                for line in self.dis_lines:
                    self.parent.addProgressPoint()
                    self.insertLine(line)

    def insertLine(self, line):
        try:
            if not line[0] == self.current_section: # Then we are entering a new section
                self.current_section = line[0]
                self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, "\n+++++++++++++++++++++++++++++++++\n"))
                self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, "    Section Name: %s\n\n" % line[0]))
            if not line[4] == self.current_function and not line[4] == None: # Then we are entering a new function
                self.current_function = line[4]
                self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, "\n=================================\n"))
                self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, "    Function Name: %s\n\n" % line[4].name))
            self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, line[0], self.disassembly_text_context_manager.createTags('section')))
            self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, " - "))
            self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, "0x%x" % line[1], self.disassembly_text_context_manager.createTags('address')))
            self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, ": "))
            self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, line[2], self.disassembly_text_context_manager.createTags('mnemonic')))
            self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, " "))
            self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, line[3], self.disassembly_text_context_manager.createTags('op_str')))
            self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, " "))
            #self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, "", self.parent.addCallback(self.text_context_manager.addComment(self.parent.addCallback(self.text_context_right_click)))
            self.parent.addCallback(self.disassembly_text_widget.insert, (INSERT, "\n"))
        except KeyboardInterrupt:
            print self.dis_lines.index(line), line

    def share(self):
        self.server.start()

if __name__ == '__main__':
    build_and_run()
