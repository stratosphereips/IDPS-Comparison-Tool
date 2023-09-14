import os
import sqlite3
from database.sqlite_db import SQLiteDB
from abstracts.abstracts import Parser
from termcolor import colored
from threading import Lock
from time import sleep

class SlipsParser(Parser):
    name = "Slips"
    # used to lock each call to commit()
    cursor_lock = Lock()
    malicious_labels = 0
    benign_labels = 0
    def init(self,
             slips_db=None):
        # this has to be the path of the sqlite3 db generated by slips with all the labels and AIDs
        self.slips_db: str = slips_db
        # caches the labeled tws
        self.labeled_tws = []

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


    def handle_labeling_tws(self, row):
        tw: int = int(row['twid'].replace("timewindow",''))
        if tw not in self.labeled_tws:
            self.db.store_tw_label('slips', tw, row['label'])
            self.labeled_tws.append(tw)

    def parse(self):
        """reads the output db of slips with the labels and stores it in this tools' db"""
        # connect to the given db
        self.connect()
        flows_count = 0
        for row in self.iterate_flows():
            flows_count += 1
            self.handle_labeling_tws(row)
            # each row is a dict
            flow = {
                'aid': row['aid'],
                'label' : row['label']
            }
            if 'malicious' in row['label'].lower():
                self.malicious_labels += 1
            else:
                self.benign_labels += 1

            self.db.store_flow(flow, 'slips_label')
            # used for printing the stats in the main.py
            self.db.store_flows_count('slips', flows_count)

        print()
        self.log(f"Total malicious labels: ", self.malicious_labels)
        self.log(f"Total benign labels: ", self.benign_labels )
