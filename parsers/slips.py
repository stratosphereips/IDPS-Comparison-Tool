import os
import subprocess
import threading
from database.sqlite_db import SQLiteDB

class SlipsParser:
    def __init__(self, slips_path, given_input: str,  output_dir: str, db: SQLiteDB):
        self.given_input: str = given_input
        # this is the output dir where this tool puts all the output files and dbs etc.
        self.output_dir = output_dir
        self.db = db
        # full path to slips installation dir
        self.slips_path: str = slips_path
        self.slips_output_dir = os.path.join(self.output_dir, 'Slips_output/')
        # this wil be a subdir inside the output dir where slips will place all of its log files
        os.mkdir(self.slips_output_dir)
        self.run()


    def parse_output(self):
        """reads the output db of slips with the labels and stores it in this tools' db"""
        ...


    def run(self):
        """
        runs slips in a thread in the bg on the given file
        """
        slips_thread = threading.Thread(target=self.exec_slips, daemon=True)
        slips_thread.start()

        # wait for slips to finish
        slips_thread.join()

        self.parse_output()






