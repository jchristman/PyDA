from Tkinter import *
from guielements import MenuBar, ToolBar, PanedWindow, ContextMenu, Textbox, Location
from disassembler.formats.common.program import CommonProgramDisassemblyFormat
from disassembler.formats.common.section import CommonSectionFormat
from disassembler.formats.common.inst import CommonInstFormat
from disassembler.formats.helpers.models import TextModel
from contextmanagers import WidgetContextManager
from redirectors import StdoutRedirector
from platform import system
import sys, os
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
        self.SAVE_PATH = self.app.save_manager.save_path

    def initUI(self):
        self.locationStack = list()

        self.app.title("PyDA")

        # Set up the Menu Bar
        self.menu_bar = MenuBar(self.app)
        self.menu_bar.addMenu('File')
        self.menu_bar.addMenuItem('File', 'Disassemble File', self.onDisassembleFile)
        self.menu_bar.addMenuItem('File', 'Load PyDA Save', self.onLoad)
        self.menu_bar.addMenuItem('File', 'Save', self.onSave)
        self.menu_bar.addMenuSeparator('File')
        self.menu_bar.addMenuItem('File', 'Exit', self.onExit)

        # Set up the Tool Bar
        # TODO: Add images to buttons with mouseover text
        self.toolbar = ToolBar(self.app, 'top')
        self.toolbar.addButton('Back', self.onBack, 'left')
        self.toolbar.addVertSeperator('left')
        self.toolbar.addButton('Disassemble File', self.onDisassembleFile, 'left')
        self.toolbar.addButton('Load', self.onLoad, 'left')
        self.toolbar.addButton('Save', self.onSave, 'left')
        self.toolbar.addVertSeperator('left')
        self.toolbar.addButton('Share', self.onShare, 'left')

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

        self.functions_listbox.bind('<Double-Button-1>', self.onFunctionDoubleClick)

        # Set up the strings listbox
        self.strings_listbox = self.left_notebook.addListboxWithScrollbar(
                'Strings', background='white', borderwidth=1,
                highlightthickness=1, relief='sunken')

        self.strings_listbox.bind('<Double-Button-1>', self.onStringDoubleClick)

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
        self.section_context_menu = ContextMenu([('Copy', self.onCopyString)])
        self.address_context_menu = ContextMenu([('Copy String', self.onCopyString), ('Copy Value', self.onCopyValue)])
        self.disass_comment_context_menu = ContextMenu([(';  Comment', self.disassComment)])
        self.data_comment_context_menu = ContextMenu([(';  Comment', self.dataComment)])
        self.disass_label_context_menu   = ContextMenu([('n  Rename Label', self.disassRenameLabel)])
        self.data_label_context_menu   = ContextMenu([('n  Rename Label', self.dataRenameLabel)])

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
                    (self.PYDA_COMMENT, 'darkgreen', self.disass_comment_context_menu),
                    (self.PYDA_LABEL, 'saddle brown', self.disass_label_context_menu),
                    (self.PYDA_BYTES, 'dark gray', None),
                    (self.PYDA_GENERIC, 'black', None),
                    (self.PYDA_ENDL, 'black', self.disass_comment_context_menu)], )

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
                    (self.PYDA_COMMENT, 'darkgreen', self.data_comment_context_menu),
                    (self.PYDA_LABEL, 'saddle brown', self.data_label_context_menu),
                    (self.PYDA_BYTES, 'dark gray', None),
                    (self.PYDA_GENERIC, 'black', None),
                    (self.PYDA_ENDL, 'black', self.data_comment_context_menu)])

        self.data_sections_textbox.context_manager = self.data_textbox_context_manager

        self.data_sections_textbox.bind('<Key>', self.keyHandler)

        # Redirect stdout to the debug window
        if self.REDIR_STDOUT:
            sys.stdout = StdoutRedirector(self.stdoutMessage)
            print "Stdout is being redirected to here"
    
    ### START OF GUI FUNCTION CALLBACKS ###
    def onCopyString(self, *args):
        print 'Copy String Selected', args

    def onCopyValue(self, *args):
        print 'Copy Value Selected', args

    def onFunctionDoubleClick(self, event):
        widget = event.widget
        selection = widget.curselection()
        name = widget.get(selection[0])
        index = self.disassembly.getLabelIndex(name, key="exe")
        self.pushCurrentLocation()
        self.goto(index, self.disassembly_textbox)

    def onStringDoubleClick(self, event):
        widget = event.widget
        selection = widget.curselection()
        name = widget.get(selection[0])
        index = self.disassembly.getLabelIndex(name, key="data")
        self.pushCurrentLocation()
        self.goto(index, self.data_sections_textbox)

    def onLoad(self):
        file_types = [] if system() == "Darwin" else [('PyDA Saves', '*.pyda'), ('All Files', '*')]
        dialog = tkFileDialog.Open(self, initialdir=self.SAVE_PATH, filetypes=file_types)
        file_name = dialog.show()
        if file_name:
            print 'Loading %s' % file_name
            self.disassembly = self.app.load(file_name)

            # TODO: Is this really necessary? Will it do what I want?
            self.initVars() # Reinitialize the settings per the load

            if isinstance(self.disassembly, CommonProgramDisassemblyFormat):
                self.clearWindows()
                print 'Load successful! Putting data now.'
                self.processDisassembly()
            else:
                print 'Load did not successfully return a CommonProgramDisassemblyFormat'

    def onSave(self):
        dialog = tkFileDialog.SaveAs(self, initialdir=self.SAVE_PATH, initialfile='.pyda')
        file_name = dialog.show()
        if file_name:
            print 'Saving to %s' % file_name
            self.app.save(file_name, self.disassembly)

    def onBack(self):
        self.popLastLocation()

    def onDisassembleFile(self):
        self.progress_bar.start()
        dialog = tkFileDialog.Open(self, initialdir=os.getcwd())
        file_name = dialog.show()
        if file_name:
            self.clearWindows()
            self.app.executor.submit(self.app.disassembler.disassemble, (file_name,), self.processDisassembly) # Start a new thread that will interact with the other process
        else:
            self.progress_bar.stop()

    def onShare(self):
        self.server.start()

    def onError(self):
        tkMessageBox.showerror("Error", "Could not determine file type from magic header.")

    def destroy(self):
        self.app.shutdown()

    def onExit(self):
        print 'Shutting down'
        self.app.shutdown()
    ### END OF GUI FUNCTION CALLBACKS ###

    def clearWindows(self):
        self.disassembly_textbox.clear()
        self.data_sections_textbox.clear()
        self.strings_listbox.delete(0,'end')
        self.functions_listbox.delete(0,'end')

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
            print str(message) + '\n',

    def getCurrentRowIndex(self, textbox):
        line, _ = textbox.index('insert').split('.')
        return line + '.0'

    def getCurrentLine(self, textbox):
        index = self.getCurrentRowIndex(textbox)
        contents = textbox.get(index, index + " lineend")
        return contents.splitlines()[0]

    def disassComment(self, event):
        self.comment(self.disassembly_textbox)

    def dataComment(self, event):
        self.comment(self.data_sections_textbox)

    def comment(self, event):
        if self.disassembly is None:
            return

        textbox = None
        if isinstance(event, Textbox):
            textbox = event
        else:
            textbox = event.widget

        tl = Toplevel(master=self.app)
        tl.title("Insert Comment")

        frame1 = Frame(tl)
        frame1.pack(side=TOP)
        frame2 = Frame(tl)
        frame2.pack()
        frame3 = Frame(tl)
        frame3.pack(side=BOTTOM)

        msg = Label(frame1, text="Please enter a comment:", height=0, width=50)
        msg.pack()

        e = Entry(frame2)
        e.pack(side=LEFT)

        def addComment(*args):
            # print 'Comment:', e.get()
            comment = e.get()
            contents = self.getCurrentLine(textbox)
            result = self.disassembly.setCommentForLine(contents, comment)
            if result:
                index = self.getCurrentRowIndex(textbox)
                textbox.redrawLine(index)

            tl.destroy()

        button1 = Button(frame2, text="Add Comment", command=addComment)
        button1.pack(side=RIGHT)

        e.focus()
        e.bind('<Return>', addComment) # Bind return to submit

        tl.grab_set() # Keeps this toplevel on top

    def disassRenameLabel(self, event):
        self.renameLabel(self.disassembly_textbox)

    def dataRenameLabel(self, event):
        self.dataRenameLabel(self.data_sections_textbox)

    def renameLabel(self, event):
        if self.disassembly is None:
            return

        textbox = None
        if isinstance(event, Textbox):
            textbox = event
        else:
            textbox = event.widget

        tl = Toplevel(master=self.app)
        tl.title('Rename Label')

        frame1 = Frame(tl)
        frame1.pack(side=TOP)
        frame2 = Frame(tl)
        frame2.pack()
        frame3 = Frame(tl)
        frame3.pack(side=BOTTOM)

        msg = Label(frame1, text='Please enter a new name:', height=0, width=50)
        msg.pack()

        e = Entry(frame2)
        e.pack(side=LEFT)

        def rename(*args):
            new_name = e.get()
            contents = self.getCurrentLine(textbox)
            result = self.disassembly.renameLabel(contents, new_name)
            if result:
                textbox.redrawLine(self.getCurrentRowIndex(textbox))
                self.functions_listbox.delete(0, 'end')
                self.strings_listbox.delete(0, 'end')
                self.populateFunctions()
                self.populateStrings()

            tl.destroy()

        button1 = Button(frame2, text="Rename", command=rename)
        button1.pack(side=RIGHT)

        e.focus()
        e.bind('<Return>', rename) # Bind return to submit

        tl.grab_set() # Keeps this toplevel on top

    def controlKeyHeld(self, event):
        return event.state & 0x004 # see here: http://infohost.nmt.edu/tcc/help/pubs/tkinter/web/event-handlers.html

    def keyHandler(self, event):
        # print event.keysym

        c = event.char
        if c == ';':
            self.comment(event)
        elif c == 'n' or c == 'N':
            self.renameLabel(event)
        elif event.keysym in ['Up', 'Down', 'Left', 'Right', 'Next', 'Prior', 'End', 'Home']:
            return
        elif event.keysym == 'Escape':
            self.popLastLocation()
        elif self.controlKeyHeld(event):
            if event.keysym == 'c':
                self.app.clipboard_clear()
                self.app.clipboard_append(event.widget.selection_get())
            elif event.keysym == 'a':
                textbox = event.widget
                textbox.tag_add('sel', '1.0', 'end')
            elif event.keysym == 'Tab':
                return

        # Otherwise, don't let this key go to the screen
        return 'break'

    def pushCurrentLocation(self):
        textbox = self.getSelectedTextbox()
        current = int(float(self.getCurrentRowIndex(textbox)))
        if current >= textbox.TCL_BUFFER_SIZE:
            current = 10
        index = current + textbox.current_data_offset
        # print "pushing:",index
        self.locationStack.append(Location(index, textbox))

    def popLastLocation(self):
        if len(self.locationStack) == 0:
            return
        location = self.locationStack.pop()
        index = location.index
        textbox = location.textbox
        # print "popping:",index
        self.goto(index, textbox)

    def goto(self, index, textbox):
        # TODO: Move this functionality out of the interface into the data structure
        # print "going to:",index
        is_disassembly = textbox == self.disassembly_textbox
        key = "exe" if is_disassembly else "data"
        fraction = index / float(self.disassembly.length(key=key))
        fraction -= .0001 # enough so that the text isn't cut off
        textbox.changeView("moveto", fraction)
        textbox.setCursor(str(index) + ".0")
        tab_index = 0 if is_disassembly else 1
        self.selectTab(tab_index)

    def selectTab(self, index):
        # TODO: make this less hacky if possible
        tab = self.right_notebook.tabs()[index]
        self.right_notebook.select(tab)

    def getSelectedTextbox(self):
        box = self.right_notebook.tabs().index(self.right_notebook.select())
        # TODO: make this less hacky if possible
        return self.disassembly_textbox if box == 0 else self.data_sections_textbox

##    def disassembleFile(self, file_name):
##        self.debug('Reading %s' % file_name)
##        self.status('Reading %s' % file_name)
##        binary = open(file_name, 'rb').read()
##        self.debug('Loading binary')
##        self.status('Loading binary')
##        self.app.disassembler.load(binary, filename=file_name)
##        self.debug('Disassembling as %s' % self.app.disassembler.getFileType())
##        self.status('Disassembling as %s' % self.app.disassembler.getFileType())
##        self.disassembly = self.app.disassembler.disassemble()
##        self.debug('Finished disassembling')
##        self.status('Finished disassembling')
##        self.app.addCallback(self.processDisassembly)

    '''
    def populateFunctions(self):
        funcs = self.disassembly.getFuncs()
        for func in funcs:
            self.app.addCallback(self.main_queue, self.functions_listbox.insert, ('end',func.name))

    def populateStrings(self):
        strings = self.disassembly.getStrings()
        for string in strings:
            self.app.addCallback(self.main_queue, self.strings_listbox.insert, ('end',string.name))
    '''

    def processDisassembly(self):
        self.status('Processing Data')

        #self.debug('Processing Functions')
        #self.populateFunctions()
        #self.debug('Processing Strings')
        #self.populateStrings()

        self.app.addCallback(self.main_queue, self.disassembly_textbox.setDataModel, (self.app.disassembler, 'exe'))
        self.app.addCallback(self.main_queue, self.data_sections_textbox.setDataModel, (self.app.disassembler, 'data', self.progress_bar))

        self.debug('Done')
        self.status('Done')
        self.progress_bar.stop()

    def printStats(self):
        stats = self.app.executor.getProfileStats()
        stats.sort_stats('cumulative').print_stats()

if __name__ == '__main__':
    build_and_run()
