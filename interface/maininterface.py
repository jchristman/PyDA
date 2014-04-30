from Tkinter import Frame, IntVar, END
from guielements import MenuBar, ToolBar, PanedWindow
from disassembler.formats.helpers import CommonProgramDisassemblyFormat
from contextmanagers import WidgetClickContextManager
from redirectors import StdoutRedirector
from platform import system
from thread import start_new_thread
from settings import PYDA_SECTION, PYDA_ADDRESS, PYDA_MNEMONIC, PYDA_OP_STR, PYDA_COMMENT, PYDA_GENERIC, PYDA_ENDL, REDIR_STDOUT
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

        # Set up the vertical paned window
        self.tl_v_window = PanedWindow(self.app, 'top', borderwidth=1, 
                relief="sunken", sashwidth=4, orient="vertical")

        # Set up the horizontal paned window and add to the vertical window
        self.tl_h_window = self.tl_v_window.addElement(
                PanedWindow(self.tl_v_window, borderwidth=1, 
                    relief="sunken", sashwidth=4))

        # Set up the two notebooks
        self.left_notebook = self.tl_h_window.addNotebook()
        self.right_notebook = self.tl_h_window.addNotebook()
        self.bottom_notebook = self.tl_v_window.addNotebook()

        # Set up the functions listbox
        self.functions_listbox = self.left_notebook.addListboxWithScrollbar(
                'Functions', background='white', borderwidth=1, 
                highlightthickness=1, relief='sunken')

        # Set up the strings listbox
        self.strings_listbox = self.left_notebook.addListboxWithScrollbar(
                'Strings', background='white', borderwidth=1, 
                highlightthickness=1, relief='sunken')

        # Set up the disassembly textbox
        self.disassembly_textbox = self.right_notebook.addTextboxWithScrollbar(
                'Disassembly', background="white", borderwidth=1, 
                highlightthickness=1, relief='sunken')

        # Set up the data section textbox
        self.data_sections_textbox = self.right_notebook.addTextboxWithScrollbar(
                'Data Sections', background="white", borderwidth=1, 
                highlightthickness=1, relief='sunken')

        # Set up the output window
        debug_frame = self.bottom_notebook.addFrame('Debug')
        debug_frame_2 = debug_frame.addFrame('bottom', 'x', False, borderwidth=1)
        debug_frame_1 = debug_frame.addFrame('top', 'both', True, borderwidth=1)
        self.debug_textbox = debug_frame_1.addTextboxWithScrollbar(
                background='white', borderwidth=1, highlightthickness=1, 
                relief='sunken')
        self.debug_entry = debug_frame_2.addEntryWithLabel(
                'Command:', 'bottom', 'x', True, background='white', 
                borderwidth=1, highlightthickness=1, relief='sunken')

        # Set up the chat window
        chat_frame = self.bottom_notebook.addFrame('Chat')
        chat_frame_2 = chat_frame.addFrame('bottom', 'x', False, borderwidth=1)
        chat_frame_1 = chat_frame.addFrame('top', 'both', True, borderwidth=1)
        self.chat_textbox = chat_frame_1.addTextboxWithScrollbar(
                background='white', borderwidth=1, highlightthickness=1, 
                relief='sunken')
        self.chat_entry = chat_frame_2.addEntryWithLabel(
                'Send:', 'bottom', 'x', True, background='white', 
                borderwidth=1, highlightthickness=1, relief='sunken')
        
        # Force the mouse to always have focus
        self.tk_focusFollowsMouse()

        # Get the appropriate button number based on system
        right_click_button = "<Button-2>" if system() == "Darwin" else "<Button-3>"

        # Create a context manager for the disassembly textbo
        self.disassembly_textbox_context_manager = WidgetClickContextManager(
                self.disassembly_textbox, right_click_button, 
                self.text_context_right_click, self.app.addCallback, 
                [(PYDA_SECTION, 'darkgreen'), (PYDA_MNEMONIC, 'blue'), 
                    (PYDA_OP_STR, 'darkblue'), (PYDA_COMMENT, 'darkgreen'), 
                    (PYDA_GENERIC, 'black'), (PYDA_ENDL, 'black')])

        self.disassembly_textbox.context_manager = self.disassembly_textbox_context_manager

        # Redirect stdout to the debug window
        if REDIR_STDOUT:
            sys.stdout = StdoutRedirector(self.stdoutMessage)
        print "Stdout is being redirected to here"

    def centerWindow(self):
        height = self.app.winfo_screenheight() * 5/6
        width = height * 16/9
        x = (self.app.winfo_screenwidth() - width)/2
        y = (self.app.winfo_screenheight() - height)/2
        self.app.geometry('%dx%d+%d+%d' % (width, height, x, y))

    def text_context_right_click(self, text_tag):
        print 'Right clicked %s' % text_tag

    def stdoutMessage(self, message):
        self.debug_textbox.appendData(message)

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

                data = disassembly.program_info + PYDA_ENDL + '\n'
 
                for line in self.dis_lines:
                    data += '%s%s: ' % (PYDA_SECTION, line[0])
                    data += '%s0x%x' % (PYDA_ADDRESS, line[1])
                    data += '%s - ' % (PYDA_GENERIC)
                    data += '%s%s  ' % (PYDA_MNEMONIC, line[2])
                    data += '%s%s  ' % (PYDA_OP_STR, line[3])
                    data += '%s%s' % (PYDA_COMMENT, '')
                    data += '%s\n' % PYDA_ENDL

                print 'Setting textbox data'
                self.app.addCallback(self.disassembly_textbox.setData, (data,))
                #self.app.addCallback(self.startTagging)

    def startTagging(self):
        start_new_thread(self.highlightPattern, (self.disassembly_textbox, 
            r'^\.[a-zA-Z]+: 0x[a-fA-F0-9]+ \- ', 'section', 'matchStart1', 
            'matchEnd1', None, 0, 3))
        start_new_thread(self.highlightPattern, (self.disassembly_textbox, 
            r'\- [a-zA-Z ]+  ', 'mnemonic', 'matchStart2', 'matchEnd2', 
            None, 2, 2))
        start_new_thread(self.highlightPattern, (self.disassembly_textbox, 
            r'  [a-zA-Z0-9 ,\-\+\*\[\]]+$', 'op_str', 'matchStart3', 
            'matchEnd3', self.disassembly_textbox_context_manager, 2))

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
                self.app.addCallback(self.disassembly_textbox.insert, (INSERT, "\n+++++++++++++++++++++++++++++++++\n"))
                self.app.addCallback(self.disassembly_textbox.insert, (INSERT, "    Section Name: %s\n\n" % line[0]))
            if not line[4] == self.current_function and not line[4] == None: # Then we are entering a new function
                self.current_function = line[4]
                self.app.addCallback(self.disassembly_textbox.insert, (INSERT, "\n=================================\n"))
                self.app.addCallback(self.disassembly_textbox.insert, (INSERT, "    Function Name: %s\n\n" % line[4].name))
            self.app.addCallback(self.disassembly_textbox.insert, (INSERT, line[0], self.disassembly_text_context_manager.createTags('section')))
            self.app.addCallback(self.disassembly_textbox.insert, (INSERT, " - "))
            self.app.addCallback(self.disassembly_textbox.insert, (INSERT, "0x%x" % line[1], self.disassembly_text_context_manager.createTags('address')))
            self.app.addCallback(self.disassembly_textbox.insert, (INSERT, ": "))
            self.app.addCallback(self.disassembly_textbox.insert, (INSERT, line[2], self.disassembly_text_context_manager.createTags('mnemonic')))
            self.app.addCallback(self.disassembly_textbox.insert, (INSERT, " "))
            self.app.addCallback(self.disassembly_textbox.insert, (INSERT, line[3], self.disassembly_text_context_manager.createTags('op_str')))
            self.app.addCallback(self.disassembly_textbox.insert, (INSERT, " "))
            #self.app.addCallback(self.disassembly_textbox.insert, (INSERT, "", self.app.addCallback(self.text_context_manager.addComment(self.app.addCallback(self.text_context_right_click)))
            self.app.addCallback(self.disassembly_textbox.insert, (INSERT, "\n"))
        except KeyboardInterrupt:
            print self.dis_lines.index(line), line'''

    def share(self):
        self.server.start()

if __name__ == '__main__':
    build_and_run()
