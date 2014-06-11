import os, cPickle

class SaveManager:
    def __init__(self, save_path='save'):
        self.save_path = save_path

    def load(self, file_path):
        with open(file_path, 'rb') as f:
            return cPickle.load(f)
        #except Exception as e: print e.message; return None

    def save(self, file_path, obj):
        with open(file_path, 'wb') as f:
            try: cPickle.dump(obj, f)
            except: pass
