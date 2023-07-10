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
        # this wil be a subdir insitde the output dir where slips will place all of its log files
        os.mkdir(self.slips_output_dir)
        self.run()

    def exec_slips(self):
        # TODO when slips is started by this tool, we should specify
        #  the output dir in slips conf, otherwise this tools will create a dir in
        command = [
            './slips.py',
            '-e', '1',
            '-f', self.given_input,
            '-o' , self.slips_output_dir,
        ]
        slips = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            cwd=self.slips_path,
        )
        # you have to get the pid before communicate()
        self.slips_pid = slips.pid
        out, error = slips.communicate()
        # if out:
        #     print(f"Zeek: {out}")
        # if error:
        #     self.print(f"Zeek error. return code: {zeek.returncode} error:{error.strip()}")

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






