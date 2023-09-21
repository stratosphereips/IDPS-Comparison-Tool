from abstracts.abstracts import Parser
import sqlite3
from os import path
class ConfusionMatrixDBParser(Parser):
    """
    Parses the given sqlite db given using -cm
    and extracts the TP, TN, FP, FN for each tool from it
    """
    name = "ConfusionMatrixDBParser"
    def init(self, db_path=None):
        self.cm_db = db_path

    def connect(self):
        self.conn = sqlite3.connect(self.cm_db, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()

    def validate_path(self) -> bool:
        """
        checks if the given db's path exists
        """
        if not path.exists(self.cm_db):
            self.log(f"Inavlid path: {self.cm_db}. "
                     f"Confusion matrix db doesn't exist.")
            return False
        return True


    def parse(self):
        if not self.validate_path():
            return False
        # valid path, connect
        self.connect()
        print(f"@@@@@@@@@@@@@@@@ connected!!")
