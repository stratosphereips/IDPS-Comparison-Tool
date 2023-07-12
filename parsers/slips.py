import os
import sqlite3
from database.sqlite_db import SQLiteDB
from termcolor import colored
from threading import Lock
from time import sleep

class SlipsParser:
    name = "Slips"
    # used to lock each call to commit()
    cursor_lock = Lock()

    def __init__(self, slips_db: str, db: SQLiteDB):
        # this has to be the path of the sqlite3 db generated by slips with all the labels and community IDs
        self.slips_db: str = slips_db
        self.db = db

    def log(self, green_txt, normal_txt):
        normal_txt = str(normal_txt)
        green_txt = str(green_txt)

        print(colored(f'[{self.name}] ', 'blue') + colored(green_txt,'green') + normal_txt)

    def connect(self):
        self.conn = sqlite3.connect(self.slips_db, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

        self.cursor = self.conn.cursor()

    def iterate_flows(self):
        """returns an iterator for all rows in the flows table in slips db"""
        # generator function to iterate over the rows
        def row_generator():
            # select all flows and altflows
            self.execute('SELECT * FROM flows;')

            while True:
                row = self.fetchone()
                if row is None:
                    break
                yield dict(row)

        # Return the combined iterator
        return iter(row_generator())


    def fetchone(self):
        """
        wrapper for sqlite fetchone to be able to use a lock
        """
        self.cursor_lock.acquire(True)
        res = self.cursor.fetchone()
        self.cursor_lock.release()
        return res

    def execute(self, query, params=None):
        """
        wrapper for sqlite execute() To avoid 'Recursive use of cursors not allowed' error
        and to be able to use a Lock()
        since sqlite is terrible with multi-process applications
        this should be used instead of all calls to commit() and execute()
        """

        try:
            self.cursor_lock.acquire(True)

            if not params:
                self.cursor.execute(query)
            else:
                self.cursor.execute(query, params)
            self.conn.commit()

            self.cursor_lock.release()
        except sqlite3.Error as e:
            if "database is locked" in str(e):
                self.cursor_lock.release()
                # Retry after a short delay
                sleep(0.1)
                self.execute(query, params=params)
            else:
                # An error occurred during execution
                print(f"Error executing query ({query}): {e}")



    def parse(self):
        """reads the output db of slips with the labels and stores it in this tools' db"""
        # connect to the given db
        self.connect()
        for row in self.iterate_flows():
            # each row is a dict
            flow = {
                'community_id': row['community_id'],
                'label' : row['label']
            }
            self.db.store_flow(flow, 'slips_label')
            self.log(f"Extracted slips label for flow: ", f"{row['community_id']}")


