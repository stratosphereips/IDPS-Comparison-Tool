from abc import ABC, abstractmethod
from multiprocessing import Process
from database.sqlite_db import SQLiteDB
from abstracts.observer import IObservable
from logger.logger import Logger


class ComparisonMethod(IObservable, ABC):
    name = ''
    def __init__(self,
                 output_dir,
                 **kwargs):
        self.output_dir = output_dir
        Process.__init__(self)
        IObservable.__init__(self)
        self.logger = Logger(self.name, self.output_dir)
        # add the logger as an observer so each msg printed to the cli will be sent to it too
        self.add_observer(self.logger)

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


    def log(self, green_txt, normal_txt, log_to_results_file=True, end="\n"):
        """
        gives the txt to the logger to log it to stdout and results.txt
        """
        self.notify_observers((normal_txt, green_txt, log_to_results_file, end))


    def __del__(self):
        self.db.close()
