from Tkinter import *
from guielements import MenuBar, ToolBar, PanedWindow, ContextMenu
from disassembler.formats.common.program import CommonProgramDisassemblyFormat
from disassembler.formats.common.section import CommonSectionFormat
from disassembler.formats.common.inst import CommonInstFormat
from disassembler.formats.helpers.models import TextModel
from contextmanagers import WidgetContextManager
from redirectors import StdoutRedirector
from platform import system
import sys
import tkFileDialog, tkMessageBox

class PyDAInterface(Frame):
    def __init__(self, app):
        Frame.__init__(self, app)
        self.app = app
        self.disassembly = None
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
        self.PYDA_BEGL = self.app.settings_manager.get('context', 'pyda-begl')
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

        self.debug_data_model = TextModel()
        self.debug_textbox.setDataModel(self.debug_data_model)

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
        
        self.chat_data_model = TextModel()
        self.chat_textbox.setDataModel(self.chat_data_model)

        # Set up the context menus
        self.section_context_menu = ContextMenu([('Copy', self.copyString)])
        self.address_context_menu = ContextMenu([('Copy String', self.copyString), ('Copy Value', self.copyValue)])
        self.comment_context_menu = ContextMenu([(';  Comment', self.comment)])
        self.label_context_menu   = ContextMenu([('Rename Label', self.renameLabel)])
        
        # Force the mouse to always have focus
        self.tk_focusFollowsMouse()

        # Get the appropriate button number based on system
        right_click_button = "<Button-2>" if system() == "Darwin" else "<Button-3>"

        dis_textbox_context_queue = self.app.createCallbackQueue()
        # Create a context manager for the disassembly textbox
        self.disassembly_textbox_context_manager = WidgetContextManager(
                self.app, dis_textbox_context_queue, self.disassembly_textbox, self.PYDA_SEP,
                self.PYDA_BEGL, right_click_button, [
                    (self.PYDA_SECTION, 'darkgreen', self.section_context_menu), 
                    (self.PYDA_ADDRESS, 'black', self.address_context_menu),
                    (self.PYDA_MNEMONIC, 'blue', None), 
                    (self.PYDA_OP_STR, 'darkblue', None), 
                    (self.PYDA_COMMENT, 'darkgreen', self.comment_context_menu),
                    (self.PYDA_LABEL, 'saddle brown', self.label_context_menu),
                    (self.PYDA_BYTES, 'dark gray', None),
                    (self.PYDA_GENERIC, 'black', None),
                    (self.PYDA_ENDL, 'black', self.comment_context_menu)], )

        self.disassembly_textbox.context_manager = self.disassembly_textbox_context_manager

        self.disassembly_textbox.bind('<Key>', self.keyHandler)

        data_textbox_context_queue = self.app.createCallbackQueue()
        # Create a context manager for the data sections textbox
        self.data_textbox_context_manager = WidgetContextManager(
                self.app, data_textbox_context_queue, self.data_sections_textbox, self.PYDA_SEP, 
                self.PYDA_BEGL, right_click_button, [
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

    def getCurrentLine(self):
        line, _ = self.disassembly_textbox.index('insert').split('.')
        contents = self.disassembly_textbox.get(line + '.0', END)
        return contents.splitlines()[0]

    def comment(self, *args):
        if self.disassembly is None:
            return
        print 'Comment selected', args

        tl = Toplevel(master=self.app)
        tl.title("Insert Comment")

        frame1 = Frame(tl)
        frame1.pack(side=TOP)
        frame2 = Frame(tl)
        frame2.pack()
        frame3 = Frame(tl)
        frame3.pack(side=BOTTOM)

        msg = Label(frame1, text="Please enter your comment:", height=0, width=50)
        msg.pack()

        e = Entry(frame2)
        e.pack(side=LEFT)

        def addComment(*args):
            print 'Comment:', e.get()
            comment = e.get()
            contents = self.getCurrentLine()
            print 'line content:',contents
            instruction = self.disassembly.search(contents, key="exe")
            if not instruction is CommonInstFormat:
                instruction.comment = comment
                print "set instruction's comment to:",comment
                self.disassembly.render()
                self.disassembly_textbox.redraw()

            tl.destroy()

        button1 = Button(frame2, text="Add Comment", command=addComment)
        button1.pack(side=RIGHT)

        e.focus()
        e.bind('<Return>', addComment) # Bind return to submit

        tl.grab_set() # Keeps this toplevel on top

    def keyHandler(self, event):
        print 'pressed:', repr(event.char)
        if event.char == ";":
            self.comment(event)
        return "break"

    def renameLabel(self, *args):
        print 'Rename selected', args

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
        self.progress_bar.start()
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
        self.disassembly = self.app.disassembler.disassemble()
        self.debug('Finished disassembling')
        self.status('Finished disassembling')
        self.processDisassembly()
        
    def processDisassembly(self):
        if isinstance(self.disassembly, CommonProgramDisassemblyFormat):
            self.status('Processing Data')
            self.debug('Processing Executable Sections')
            ex_secs = self.disassembly.getExecutableSections()
            for sec in ex_secs:
                if isinstance(sec, CommonSectionFormat):
                    for func in sec.functions:
                        self.app.addCallback(self.main_queue, self.functions_listbox.insert, ('end',func.name))
                    for string in sec.strings_list:
                        self.app.addCallback(self.main_queue, self.strings_listbox.insert, ('end',string.contents))
            self.app.addCallback(self.main_queue, self.disassembly_textbox.setDataModel, (self.disassembly, 'exe'))

            self.debug('Processing Data Sections')
            data_secs = self.disassembly.getDataSections() # Get the data model for the textbox
            for sec in data_secs:
                if isinstance(sec, CommonSectionFormat):
                    for string in sec.strings_list:
                        self.app.addCallback(self.main_queue, self.strings_listbox.insert, ('end',string.contents))
            self.app.addCallback(self.main_queue, self.data_sections_textbox.setDataModel, (self.disassembly, 'data', self.progress_bar))
            self.debug('Done')
            self.status('Done')
            self.progress_bar.stop()

    def printStats(self):
        stats = self.app.executor.getProfileStats()
        stats.sort_stats('cumulative').print_stats()

    def share(self):
        self.server.start()

if __name__ == '__main__':
    build_and_run()
