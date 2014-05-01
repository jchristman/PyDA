from Tkinter import Frame, StringVar, IntVar, END, OptionMenu
from guielements import MenuBar, ToolBar, PanedWindow
from disassembler.formats.helpers import CommonProgramDisassemblyFormat
from contextmanagers import WidgetClickContextManager
from redirectors import StdoutRedirector
from platform import system
from thread import start_new_thread
from settings import DEBUG, PYDA_SECTION, PYDA_ADDRESS, PYDA_MNEMONIC, PYDA_OP_STR, PYDA_COMMENT, PYDA_GENERIC, PYDA_ENDL, REDIR_STDOUT
import sys, time #FIXME
import tkFileDialog, tkMessageBox

class PyDAInterface(Frame):
    def __init__(self, app):
        Frame.__init__(self, app)
        self.app = app
        self.main_queue = self.app.createCallbackQueue()
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
        self.toolbar.addButton('Test', self.test, 'right')
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

        dis_textbox_context_queue = self.app.createCallbackQueue()
        # Create a context manager for the disassembly textbo
        self.disassembly_textbox_context_manager = WidgetClickContextManager(
                self.app, dis_textbox_context_queue, self.disassembly_textbox,
                right_click_button, self.text_context_right_click,
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
        string_var = StringVar()
        context_menu = OptionMenu(self.app, string_var, 'Test 1', 'Test 2', 'Test 3')
        context_menu.pack()

    def stdoutMessage(self, message):
        self.debug_textbox.appendData(message)

    def status(self, message):
        self.app.addCallback(self.main_queue, self._status, (message,))

    def _status(self, message):
        self.status_label['text'] = message

    def debug(self, message):
        if DEBUG:
            print message + '\n',

    def contextMenu(self, e):
        print vars(e)

    def onError(self):
        tkMessageBox.showerror("Error", "Could not determine file type from magic header.")

    def onExit(self):
        self.quit()

    ########### PyDA Specific Functions ###########
    def importFile(self):
        # Returns the opened file
        dialog = tkFileDialog.Open(self)
        file_name = dialog.show()
        start_new_thread(self.disassembleFile, (file_name,))

    def disassembleFile(self, file_name):
        if not file_name == '':
            self.status('Reading %s' % file_name)
            self.debug('Reading %s' % file_name)
            binary = open(file_name, 'rb').read()

            self.app.disassembler.load(binary)
            self.debug('Starting disassembly')
            self.status('Disassembling as %s' % self.app.disassembler.getFileType())
            disassembly = self.app.disassembler.disassemble()
            self.debug('Finished disassembly')
            
            if isinstance(disassembly, CommonProgramDisassemblyFormat):
                for function in disassembly.functions:
                    self.app.addCallback(self.main_queue, self.functions_listbox.insert, (END, function.name))

                self.debug('Processing disassembly')
                self.status('Processing disassembly')
                t0 = time.time()
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

                t1 = time.time()
                print 'Timing data: %.04f' % (t1 - t0)

                self.status('Done.')
                self.debug('Putting the data into the disassembly tab')
                self.app.addCallback(self.main_queue, self.disassembly_textbox.setData, (data,))

    def test(self):
        dialog = tkFileDialog.Open(self)
        file_name = dialog.show()
        start_new_thread(self._test, (file_name,))

    def _test(self, file_name):
        print 'Reading the file'
        binary = open(file_name, 'rb').read()
        print 'Finding File Format'
        self.app.disassembler.load(binary)
        print 'Disassembling'
        disassembly = self.app.disassembler.disassemble()
        if isinstance(disassembly, CommonProgramDisassemblyFormat):
            print 'Running generator'
            t0 = time.time()
            data = disassembly.program_info + PYDA_ENDL + '\n'
            for line,line_func in disassembly.getLines(disassembly.getSectionByName('.text')):
                data += line
            t1 = time.time() 
            print 'Timing data: %.04f' % (t1 - t0)

            self.app.addCallback(self.main_queue, self.disassembly_textbox.setData, (data,))

    def share(self):
        self.server.start()

if __name__ == '__main__':
    build_and_run()
