from Tkinter import Frame, IntVar, END
from guielements import MenuBar, ToolBar, PanedWindow, ContextMenu
from disassembler.formats.common.program import CommonProgramDisassemblyFormat
from contextmanagers import WidgetClickContextManager
from redirectors import StdoutRedirector
from platform import system
import sys
import tkFileDialog, tkMessageBox

class PyDAInterface(Frame):
    def __init__(self, app):
        Frame.__init__(self, app)
        self.app = app
        self.main_queue = self.app.createCallbackQueue()
        self.initVars()
        self.initUI()
        self.centerWindow()

    def initVars(self):
        self.PYDA_SEP = self.app.settings_manager.get('context', 'pyda-sep')
        self.PYDA_SECTION = self.app.settings_manager.get('context', 'pyda-section')
        self.PYDA_ADDRESS = self.app.settings_manager.get('context', 'pyda-address')
        self.PYDA_MNEMONIC = self.app.settings_manager.get('context', 'pyda-mnemonic')
        self.PYDA_OP_STR = self.app.settings_manager.get('context', 'pyda-op-str')
        self.PYDA_COMMENT = self.app.settings_manager.get('context', 'pyda-comment')
        self.PYDA_LABEL = self.app.settings_manager.get('context', 'pyda-label')
        self.PYDA_BYTES = self.app.settings_manager.get('context', 'pyda-bytes')
        self.PYDA_GENERIC = self.app.settings_manager.get('context', 'pyda-generic')
        self.PYDA_ENDL = self.app.settings_manager.get('context', 'pyda-endl')
        self.REDIR_STDOUT = self.app.settings_manager.getint('debugging', 'redirect-stdout')
        self.DEBUG = self.app.settings_manager.getint('debugging', 'debug-on')
        self.PROFILE = self.app.settings_manager.getint('debugging', 'profiler-on')
        self.TEXTBOX_BUFFER_SIZE = self.app.settings_manager.getint('gui', 'textbox-buffer-size')
        self.TEXTBOX_BUFFER_LOW_CUTOFF = self.app.settings_manager.getfloat('gui', 'textbox-buffer-low-cutoff')
        self.TEXTBOX_BUFFER_HIGH_CUTOFF = self.app.settings_manager.getfloat('gui', 'textbox-buffer-high-cutoff')
        self.TEXTBOX_MOVETO_YVIEW = self.app.settings_manager.getfloat('gui', 'moveto-yview')
        self.TEXTBOX_MAX_LINES_JUMP = self.app.settings_manager.getint('gui', 'max-lines-jump')
        self.NUM_OPCODE_BYTES_SHOWN = self.app.settings_manager.getint('disassembly','num-opcode-bytes-shown')
        self.MIN_STRING_SIZE = self.app.settings_manager.getint('disassembly','min-string-size')

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

        self.functions_listbox.bind('<Double-Button-1>', self.functionDoubleClick)

        # Set up the strings listbox
        self.strings_listbox = self.left_notebook.addListboxWithScrollbar(
                'Strings', background='white', borderwidth=1, 
                highlightthickness=1, relief='sunken')

        self.strings_listbox.bind('<Double-Button-1>', self.stringDoubleClick)

        # Set up the disassembly textbox
        self.disassembly_textbox = self.right_notebook.addTextboxWithScrollbar(
                'Disassembly', tcl_buffer_size=self.TEXTBOX_BUFFER_SIZE,
                tcl_buffer_low_cutoff=self.TEXTBOX_BUFFER_LOW_CUTOFF,
                tcl_buffer_high_cutoff=self.TEXTBOX_BUFFER_HIGH_CUTOFF,
                tcl_moveto_yview=self.TEXTBOX_MOVETO_YVIEW,
                max_lines_jump=self.TEXTBOX_MAX_LINES_JUMP,
                background="white", borderwidth=1, highlightthickness=1, relief='sunken')

        # Set up the data section textbox
        # self.data_sections_textbox = self.right_notebook.addTextboxWithScrollbar(
        #         'Data Sections', background="white", borderwidth=1, 
        #         highlightthickness=1, relief='sunken')
        self.data_sections_textbox = self.right_notebook.addTextboxWithScrollbar(
                'Data Sections', tcl_buffer_size=self.TEXTBOX_BUFFER_SIZE,
                tcl_buffer_low_cutoff=self.TEXTBOX_BUFFER_LOW_CUTOFF,
                tcl_buffer_high_cutoff=self.TEXTBOX_BUFFER_HIGH_CUTOFF,
                tcl_moveto_yview=self.TEXTBOX_MOVETO_YVIEW,
                max_lines_jump=self.TEXTBOX_MAX_LINES_JUMP,
                background="white", borderwidth=1, highlightthickness=1, relief='sunken')

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

        # Set up the context menus
        self.section_context_menu = ContextMenu([('Copy', self.copyString)])
        self.address_context_menu = ContextMenu([('Copy String', self.copyString), ('Copy Value', self.copyValue)])
        
        # Force the mouse to always have focus
        self.tk_focusFollowsMouse()

        # Get the appropriate button number based on system
        right_click_button = "<Button-2>" if system() == "Darwin" else "<Button-3>"

        dis_textbox_context_queue = self.app.createCallbackQueue()
        # Create a context manager for the disassembly textbox
        self.disassembly_textbox_context_manager = WidgetClickContextManager(
                self.app, dis_textbox_context_queue, self.disassembly_textbox, self.PYDA_SEP,
                right_click_button, [
                    (self.PYDA_SECTION, 'darkgreen', self.section_context_menu), 
                    (self.PYDA_ADDRESS, 'black', self.address_context_menu),
                    (self.PYDA_MNEMONIC, 'blue', None), 
                    (self.PYDA_OP_STR, 'darkblue', None), 
                    (self.PYDA_COMMENT, 'darkgreen', None),
                    (self.PYDA_LABEL, 'saddle brown', None),
                    (self.PYDA_BYTES, 'dark gray', None),
                    (self.PYDA_GENERIC, 'black', None),
                    (self.PYDA_ENDL, 'black', None)])

        self.disassembly_textbox.context_manager = self.disassembly_textbox_context_manager

        data_textbox_context_queue = self.app.createCallbackQueue()
        # Create a context manager for the data sections textbox
        self.data_textbox_context_manager = WidgetClickContextManager(
                self.app, data_textbox_context_queue, self.data_sections_textbox, self.PYDA_SEP, 
                right_click_button, [
                    (self.PYDA_SECTION, 'darkgreen', None), 
                    (self.PYDA_MNEMONIC, 'blue', None), 
                    (self.PYDA_OP_STR, 'darkblue', None), 
                    (self.PYDA_COMMENT, 'darkgreen', None),
                    (self.PYDA_LABEL, 'saddle brown', None), 
                    (self.PYDA_BYTES, 'dark gray', None), 
                    (self.PYDA_GENERIC, 'black', None), 
                    (self.PYDA_ENDL, 'black', None)])

        self.data_sections_textbox.context_manager = self.data_textbox_context_manager

        # Redirect stdout to the debug window
        if self.REDIR_STDOUT:
            sys.stdout = StdoutRedirector(self.stdoutMessage)
            print "Stdout is being redirected to here"

    def centerWindow(self):
        height = self.app.winfo_screenheight() * 5/6
        width = height * 16/9
        x = (self.app.winfo_screenwidth() - width)/2
        y = (self.app.winfo_screenheight() - height)/2
        self.app.geometry('%dx%d+%d+%d' % (width, height, x, y))

    def stdoutMessage(self, message):
        self.debug_textbox.appendData(message, True)

    def status(self, message):
        self.app.addCallback(self.main_queue, self._status, (message,))

    def _status(self, message):
        self.status_label['text'] = message

    def debug(self, message):
        if self.DEBUG:
            print message + '\n',

    def onError(self):
        tkMessageBox.showerror("Error", "Could not determine file type from magic header.")

    def destroy(self):
        self.app.shutdown()
    
    def onExit(self):
        print 'Shutting down'
        self.app.shutdown()

    def copyString(self, *args):
        print 'Copy String Selected', args

    def copyValue(self, *args):
        print 'Copy Value Selected', args

    def functionDoubleClick(self, event):
        widget = event.widget
        selection = widget.curselection()
        value = widget.get(selection[0])
        print 'selection:',selection,', value:',value

    def stringDoubleClick(self, event):
        widget = event.widget
        selection = widget.curselection()
        value = widget.get(selection[0])
        print 'selection:',selection,', value:',value

    def importFile(self):
        dialog = tkFileDialog.Open(self)
        file_name = dialog.show()
        if file_name:
            self.app.executor.submit(self.disassembleFile, file_name)

    def disassembleFile(self, file_name):
        self.debug('Reading %s' % file_name)
        self.status('Reading %s' % file_name)
        binary = open(file_name, 'rb').read()
        self.debug('Loading binary')
        self.status('Loading binary')
        self.app.disassembler.load(binary, filename=file_name)
        self.debug('Disassembling as %s' % self.app.disassembler.getFileType())
        self.status('Disassembling as %s' % self.app.disassembler.getFileType())
        disassembly = self.app.disassembler.disassemble()
        self.debug('Finished disassembling')
        self.status('Finished disassembling')
        self.processDisassembly(disassembly)
        
    def processDisassembly(self, disassembly):
        if isinstance(disassembly, CommonProgramDisassemblyFormat):
            self.status('Processing Data')
            self.debug('Processing Functions')
            #for function in disassembly.functions:
            #    self.app.addCallback(self.main_queue, self.functions_listbox.insert, ('end', function.name))

            self.debug('Processing Strings')
            #for string in disassembly.strings:
            #    self.app.addCallback(self.main_queue, self.strings_listbox.insert, ('end', string.contents))

            self.debug('Processing Executable Sections')
            data = disassembly.program_info + self.PYDA_ENDL + '\n'
            ex_secs = disassembly.getExecutableSections() # Get the data model for the textbox
            self.app.addCallback(self.main_queue, self.disassembly_textbox.setDataModel, (ex_secs,))

            self.debug('Processing Data Sections')
            data = disassembly.program_info + self.PYDA_ENDL + '\n'
            data_secs = disassembly.getDataSections() # Get the data model for the textbox
            self.app.addCallback(self.main_queue, self.data_sections_textbox.setDataModel, (data_secs,))
            self.status('Done')

    def printStats(self):
        stats = self.app.executor.getProfileStats()
        stats.sort_stats('cumulative').print_stats()

    def share(self):
        self.server.start()

if __name__ == '__main__':
    build_and_run()
