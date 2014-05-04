from interface import app
from concurrent.futures import ThreadPoolExecutor
from disassembler.Disassembler import Disassembler
from settings.settings import SettingsManager
from server.PyDAServer import PyDAServer
import yappi

class PyDA:
    def __init__(self):
        settings_manager = SettingsManager()
        max_workers = settings_manager.getint('application', 'max-workers')
        dis = Disassembler()
        executor = ThreadPoolExecutor(max_workers=max_workers)
        server = PyDAServer('0.0.0.0',9000)
        app.build_and_run(dis, executor, server)

if __name__ == '__main__':
    pyda = PyDA()
