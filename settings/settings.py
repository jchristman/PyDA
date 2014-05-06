from ConfigParser import ConfigParser
import os

try:
    CONFIG_PATH = os.path.dirname(__file__) + os.path.sep + 'PyDA.conf'
except:
    CONFIG_PATH = 'PyDA.conf' # this will only happen if we run this script directly

class SettingsManager(ConfigParser):
    def __init__(self, config_path=CONFIG_PATH):
        ConfigParser.__init__(self, allow_no_value=True)
        self.config_path = config_path
        try:
            self.read(self.config_path)
        except: # It doesn't exist!
            self.createDefaultConfig()
        
    def save(self):
        with open(self.config_path, 'wb') as config_file:
            self.write(config_file)

    def createDefaultConfig(self):
        self.add_section('debugging')
        self.set('debugging', 'redirect-stdout', '1')
        self.set('debugging', 'profiler-on', '0')

        self.add_section('application')
        self.set('application', 'queue-process-amount', '7000')
        self.set('application', 'queue-process-delay', '50')
        self.set('application', 'max-workers', '8')

        self.add_section('gui')
        self.set('gui', 'textbox-buffer-size', '1000')
        self.set('gui', 'textbox-buffer-low-cutoff', '0.49')
        self.set('gui', 'textbox-buffer-high-cutoff', '0.51')
        self.set('gui', 'moveto-yview', '0.50')
        self.set('gui', 'max-lines-jump', '40')

        self.add_section('context')
        self.set('context', 'pyda-sep', 'P_')
        self.set('context', 'pyda-section', '%(pyda-sep)sS')
        self.set('context', 'pyda-address', '%(pyda-sep)sA')
        self.set('context', 'pyda-mnemonic', '%(pyda-sep)sM')
        self.set('context', 'pyda-op-str', '%(pyda-sep)sO')
        self.set('context', 'pyda-comment', '%(pyda-sep)sC')
        self.set('context', 'pyda-label', '%(pyda-sep)sL')
        self.set('context', 'pyda-bytes', '%(pyda-sep)sB')
        self.set('context', 'pyda-generic', '%(pyda-sep)sG')
        self.set('context', 'pyda-endl', '%(pyda-sep)sN')

        self.add_section('disassembly')
        self.set('disassembly', 'num-opcode-bytes-shown', '5')
        self.set('disassembly', 'min-string-size', '5')

        self.save()
                 
