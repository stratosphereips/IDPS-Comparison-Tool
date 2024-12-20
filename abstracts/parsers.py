from abc import ABC, abstractmethod
from multiprocessing import Process
from termcolor import colored
from database.sqlite_db import SQLiteDB
from abstracts.observer import IObservable
from logger.logger import Logger
from typing import Optional


class Parser(IObservable):
    name = ''
    def __init__(self,
                 output_dir: str,
                 results_path: Optional[str]=None,
                 *args):
        super(Parser, self).__init__()
        # init the logger
        self.results_path = results_path
        self.logger = Logger(self.name, output_dir)
        # add the logger as an observer so each msg printed to the cli will be sent to it too
        self.add_observer(self.logger)

        Process.__init__(self)
        self.db = SQLiteDB(output_dir)

        self.init(args)

    @abstractmethod
    def init(self, *args):
        """
        the goal of this is to have one common __init__()
        for all modules, which is the one in this file
        this init will have access to all keyword args passes
         when initializing the module
        """
    
    def read_configuration(self):
        """extracts the values the parser is going to use from config.yaml"""
        ...
    
    def log(self, colored_txt, normal_txt, log_to_results_file=True,
            end="\n", error=False):
        """
        gives the txt to the logger to log it to stdout and results.txt
        """
        self.notify_observers((normal_txt, colored_txt, log_to_results_file,
                               end, error))

    @abstractmethod
    def parse(self):
        """main method of each parser"""

    def __del__(self):
        self.db.close()
