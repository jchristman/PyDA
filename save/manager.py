import os, cPickle

class SaveManager:
    def __init__(self, save_path='save'):
        self.save_path = save_path

    def load(self, file_path):
        with open(file_path, 'wb') as f:
            return cPickle.load(f)

    def save(self, file_path, obj):
        with open(file_path, 'wb') as f:
            cPickle.dump(obj, f)
