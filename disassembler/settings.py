import importlib, formats

FORMATS_DIR = 'formats'

def import_all_classes():
    imported_formats = []
    for f in formats.filenames:
        imported_formats.append(importlib.import_module('disassembler' + '.' + FORMATS_DIR + '.' + f))
    return imported_formats

IMPORTED_FORMATS = import_all_classes()
