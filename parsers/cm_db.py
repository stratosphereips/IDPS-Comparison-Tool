from abstracts.parsers import Parser
from abstracts.dbs import IDB
import sqlite3
from os import path

class ConfusionMatrixDBParser(IDB):
    """
    Parses the given sqlite db given using -cm
    and extracts the TP, TN, FP, FN for each tool from it
    """
    name = "ConfusionMatrixDBParser"
    cm_results = {}
    def init(self, db_full_path=None):
        pass

    def parse(self):
        # read the values from the given db and store them in this tools' db
        # to  be able to use them later
        for tool in ("slips", 'suricata'):
            cm = self.select('performance_errors',
                             '*',
                             condition=f'tool = "{tool}"',
                             fetch='one')
            if cm:
                self.cm_results[tool] = {
                    'TP': int(cm[1]),
                    'FP': int(cm[2]),
                    'TN': int(cm[3]),
                    'FN': int(cm[4])
                }

            else:
                self.log(f"Tool {tool} doesn't have CM values! terminating.",'')
        return self.cm_results