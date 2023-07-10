import os
import json
from database.sqlite_db import SQLiteDB

class SlipsParser:
    def __init__(self, given_input: str, db: SQLiteDB):
        self.given_input: str = given_input
        self.db = db

    def start(self):
        """
        runs slips in a thread in the bg on the given file
        """
        pass

