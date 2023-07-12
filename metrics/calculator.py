from database.sqlite_db import SQLiteDB
from termcolor import colored
import json


class Calulator:
    name = "MetricsCalculator"
    def __init__(self, db: SQLiteDB):
        self.db = db

    def log(self, green_txt, normal_txt):
        normal_txt = str(normal_txt)
        green_txt = str(green_txt)

        print(colored(f'[{self.name}] ', 'blue') + colored(green_txt,'green') + normal_txt)


    def FPs(self):
        """
        returns the false positives
        :return:
        """
        ...


    def fpr(self):
        ...