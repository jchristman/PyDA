from Tkinter import PanedWindow, Frame, Label, Text, Entry, Scrollbar, Listbox, Button, IntVar, BOTH, END, INSERT, LEFT
from ttk import Notebook
from guielements import MenuBar, ToolBar
from disassembler.formats.helpers import CommonProgramDisassemblyFormat
from contextmanagers import WidgetClickContextManager
from redirectors import StdoutRedirector
from platform import system
from thread import start_new_thread
import sys
import tkFileDialog, tkMessageBox

class PyDAInterface(Frame):
    def __init__(self, app):
        Frame.__init__(self, app)
        self.app = app
        self.initUI()
        self.centerWindow()

    def initUI(self):
        self.app.title("PyDA")

        # Set up the Menu Bar
        self.menu_bar = MenuBar(self.app)
        self.menu_bar.addMenu('File')
        self.menu_bar.addMenuItem('File', 'Import', self.importFile)
        self.menu_bar.addMenuSeparator('File')
        self.menu_bar.addMenuItem('File', 'Exit', self.onExit)        

        # Set up the Tool Bar
        self.toolbar = ToolBar(self.app, 'top')
        self.toolbar.addButton('Import', self.importFile, 'left')
        self.toolbar.addButton('Share', self.share, 'right')
        #############################
        
        # Set up the status bar ##
        self.status_bar = ToolBar(self.app, 'bottom', relief='sunken', borderwidth=2)
        self.status_bar.addLabel('Status:', 'left')
        self.status_label = self.status_bar.addLabel('Ready', 'left')
        self.progress_bar = self.status_bar.addProgressBar('right', length=200, mode='indeterminate')

        self.top_level_window = PanedWindow(borderwidth=1, relief="sunken", sashwidth=4, orient="vertical")
        self.main_window = PanedWindow(self.top_level_window, borderwidth=1, relief="sunken", sashwidth=4)

        self.right_notebook = Notebook(self.main_window)
        self.left_notebook = Notebook(self.main_window)

        ## Set up the main PyDA Disassembly Window ##
        self.disassembly_frame = Frame(self.right_notebook)
        self.dis_text_scroller = Scrollbar(self.disassembly_frame, orient="vertical", borderwidth=1)
        self.disassembly_text_widget = Text(self.disassembly_frame, background="white", borderwidth=1, highlightthickness=1, 
                                            yscrollcommand=self.dis_text_scroller.set)
        self.dis_text_scroller.config(command=self.disassembly_text_widget.yview)
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
                                                self.text_context_right_click, [('section','darkgreen'),
                                                ('mnemonic','blue'),('op_str','darkblue'),('comment','darkgreen')])
        sys.stdout = StdoutRedirector(self.stdoutMessage)
        print "Stdout is being redirected to here"

    def centerWindow(self):
        height = self.app.winfo_screenheight()*3/4
        width = height * 16 / 9
        x = (self.app.winfo_screenwidth() - width)/2
        y = (self.app.winfo_screenheight() - height)/2
        self.app.geometry('%dx%d+%d+%d' % (width, height, x, y))

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
            self.app.stopProgressMonitor()
            self.status('Finished')

    def status(self, message):
        self.app.addCallback(self._status, (message,))

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

            self.app.disassembler.load(binary)
            disassembly = self.app.disassembler.disassemble()
            
            if isinstance(disassembly, CommonProgramDisassemblyFormat):
                for function in disassembly.functions:
                    self.app.addCallback(self.functions_listbox.insert, (END, function.name))

                self.dis_lines = disassembly.serialize()
                lines_to_process = len(self.dis_lines)
                
                self.current_section = ''
                self.current_function = ''
                self.app.addCallback(self.disassembly_text_widget.delete, (0.0, END))

                data = disassembly.program_info + '\n'
 
                for line in self.dis_lines:
                    data += '%s: 0x%x - %s  %s\n' % (line[0], line[1], line[2], line[3])

                self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, data))
                self.app.addCallback(self.startTagging)

    def startTagging(self):
        start_new_thread(self.highlightPattern, (self.disassembly_text_widget, r'^\.[a-zA-Z]+: 0x[a-fA-F0-9]+ \- ', 
            'section', 'matchStart1', 'matchEnd1', None, 0, 3))
        start_new_thread(self.highlightPattern, (self.disassembly_text_widget, r'\- [a-zA-Z ]+  ',
            'mnemonic', 'matchStart2', 'matchEnd2', None, 2, 2))
        start_new_thread(self.highlightPattern, (self.disassembly_text_widget, r'  [a-zA-Z0-9 ,\-\+\*\[\]]+$', 
            'op_str', 'matchStart3', 'matchEnd3', self.disassembly_text_context_manager, 2))

    def highlightPattern(self, widget, pattern, tag, startMark, endMark, widget_context_manager=None, offset=0, endOffset=0):
        '''Apply the given tag to all text that matches the given pattern

        If 'regexp' is set to True, pattern will be treated as a regular expression
        '''

        start = widget.index("1.0")
        end = widget.index("end")
        widget.mark_set(startMark,start)
        widget.mark_set(endMark,start)
        widget.mark_set("searchLimit", end)

        count = IntVar()
        while True:
            index = widget.search(pattern, endMark, "searchLimit",
                                count=count, regexp=True)
            if index == "": break
            index = index.split('.')
            index = index[0] + '.' + str(int(index[1]) + offset)
            widget.mark_set(startMark, index)
            widget.mark_set(endMark, "%s+%sc" % (index,count.get() - offset - endOffset))
            
            if widget_context_manager:
                tag, uuid = widget_context_manager.createTags(tag)
                widget.tag_add(tag, startMark, endMark)
                widget.tag_add(uuid, startMark, endMark)
            else:
                widget.tag_add(tag, startMark, endMark)
    '''
    def insertLine(self, line):
        try:
            if not line[0] == self.current_section: # Then we are entering a new section
                self.current_section = line[0]
                self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, "\n+++++++++++++++++++++++++++++++++\n"))
                self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, "    Section Name: %s\n\n" % line[0]))
            if not line[4] == self.current_function and not line[4] == None: # Then we are entering a new function
                self.current_function = line[4]
                self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, "\n=================================\n"))
                self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, "    Function Name: %s\n\n" % line[4].name))
            self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, line[0], self.disassembly_text_context_manager.createTags('section')))
            self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, " - "))
            self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, "0x%x" % line[1], self.disassembly_text_context_manager.createTags('address')))
            self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, ": "))
            self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, line[2], self.disassembly_text_context_manager.createTags('mnemonic')))
            self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, " "))
            self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, line[3], self.disassembly_text_context_manager.createTags('op_str')))
            self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, " "))
            #self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, "", self.app.addCallback(self.text_context_manager.addComment(self.app.addCallback(self.text_context_right_click)))
            self.app.addCallback(self.disassembly_text_widget.insert, (INSERT, "\n"))
        except KeyboardInterrupt:
            print self.dis_lines.index(line), line'''

    def share(self):
        self.server.start()

if __name__ == '__main__':
    build_and_run()
