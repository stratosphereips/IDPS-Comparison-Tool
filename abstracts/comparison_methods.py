from abc import ABC, abstractmethod
from multiprocessing import Process
from termcolor import colored
from database.sqlite_db import SQLiteDB


class ComparisonMethod(ABC):
    name = ''
    def __init__(self,
                 output_dir,
                 **kwargs):
        Process.__init__(self)
        self.output_dir = output_dir
        self.db = SQLiteDB(self.output_dir)
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
        end = '\n'
        print(f"{colored(f'[{self.name}] ', 'blue')} "
              f"{colored(green_txt, 'green')} "
              f"{normal_txt}",
              end=end)

    def __del__(self):
        self.db.close()
