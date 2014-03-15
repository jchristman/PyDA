import os, glob, importlib

FORMATS_DIR = 'formats'

def import_all_classes():
    filenames = [os.path.basename(f)[:-3] for f in glob.glob(FORMATS_DIR + os.path.sep + "*.py")]
    filenames.remove('__init__')
    formats = []
    for f in filenames:
        formats.append(importlib.import_module(FORMATS_DIR + '.' + f))
    return formats

IMPORTED_FORMATS = import_all_classes()
