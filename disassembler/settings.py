import os, glob, importlib

FORMATS_DIR = 'formats'

def import_all_classes():
    filenames = [os.path.basename(f)[:-3] for f in glob.glob('disassembler' + os.path.sep + FORMATS_DIR + os.path.sep + "*.py")]
    
    formats = []
    for f in filenames:
        formats.append(importlib.import_module('disassembler' + '.' + FORMATS_DIR + '.' + f))
    return formats

IMPORTED_FORMATS = import_all_classes()
