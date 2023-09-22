from abc import ABC, abstractmethod
from multiprocessing import Process
from termcolor import colored
from database.sqlite_db import SQLiteDB
from abstracts.observer import IOvservable
from logger.logger import Logger
class Parser(IOvservable):
    name = ''
    def __init__(self,
                 output_dir,
                 results_path=None,
                 **kwargs):
        super(Parser, self).__init__(results_path)
        Process.__init__(self)
        self.db = SQLiteDB(output_dir)
        # add the logger as an observer so each msg printed to the cli will be sent to it too
        self.logger = Logger(self.name)
        self.add_observer(self.logger)

        self.init(**kwargs)

    @abstractmethod
    def init(self, **kwargs):
        """
        the goal of this is to have one common __init__()
        for all modules, which is the one in this file
        this init will have access to all keyword args passes
         when initializing the module
        """

    def log(self, green_txt, normal_txt):
        """
        logs the txt to stdout
        """
        msg = f"{colored(f'[{self.name}] ', 'blue')} " \
              f"{colored(green_txt, 'green')} " \
              f"{normal_txt}"

        end = '\r' if 'Parsed' in green_txt else '\n'
        print(msg, end=end)

        msg = f"{self.name} {green_txt} {normal_txt}"
        self.notify_observers(msg)

    @abstractmethod
    def parse(self):
        """main method of each parser"""

    def __del__(self):
        self.db.close()
