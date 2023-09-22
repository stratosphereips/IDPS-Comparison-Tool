import os
import sqlite3
from database.sqlite_db import SQLiteDB
from abstracts.parsers import Parser
from termcolor import colored
from utils.timestamp_handler import TimestampHandler
from threading import Lock
from time import sleep

class SlipsParser(Parser):
    name = "Slips"
    # used to lock each call to commit()
    cursor_lock = Lock()
    malicious_labels = 0
    benign_labels = 0
    discarded_tw_labels = 0

    def init(self,
             slips_db=None):
        # this has to be the path of the sqlite3 db generated by slips with all the labels and AIDs
        self.slips_db: str = slips_db
        # caches the labeled tws
        self.labeled_tws = []
        self.timestamp_handler = TimestampHandler()

    def connect(self):
        self.conn = sqlite3.connect(self.slips_db, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

        self.cursor = self.conn.cursor()


    def iterate(self, table: str):
        """
        returns an iterator for all rows in the flows table in slips db
        :param table: table to iterate in slips db
        """
        # generator function to iterate over the rows
        def row_generator():
            # select all flows and altflows
            self.execute(f'SELECT * FROM {table};')

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


    def handle_labeling_tws(self, row: dict):
        """
        gets the timewindow that corresponds to this slips tw and marks it as malicious
        :param row:  dict with
        :return:
        """
        return
        #TODO
        # tw: int = int(row['twid'].replace("timewindow",''))
        # if tw not in self.labeled_tws:
        #     self.db.store_tw_label('slips', tw, row['label'])
        #     self.labeled_tws.append(tw)

    def warn_about_discarded_alert(self, alert: dict):
        """
        prints a warning when the tool i sdiscarding an alert detected by slips
        :param alert:
        :return:
        """
        self.discarded_tw_labels += 1
        gt_start_time, gt_end_time = self.db.get_timewindows_limit()

        gt_start_time = self.timestamp_handler.convert_to_human_readable(gt_start_time)
        gt_end_time = self.timestamp_handler.convert_to_human_readable(gt_end_time)
        slips_start_time =  self.timestamp_handler.convert_to_human_readable(alert['tw_start'])
        slips_end_time =  self.timestamp_handler.convert_to_human_readable(alert['tw_end'])

        self.log(f"Problem marking malicious tw: "
                 f"Slips marked timewindow {alert['timewindow']} as malicious,"
                 f"timewindow start: {slips_start_time} end: {slips_end_time}. "
                 f"meanwhile tws in gt start at: {gt_start_time} and end at: {gt_end_time}. ",
                 "discarding alert.")


    def parse_alerts_table(self):
        """
        parses the labels set by slips for each timewindow, and marks them as malicious in this tools' db
        """
        def mark_tw_as_malicious(ts: str, ip: str):
            """
            marks the tw of the given ts as malicious by slips in the db
            :param ts: timestamp of the start or end of a malicious alert
            :param ip: the source ip that was marked as malicious by slips
            """

            ts = float(ts)
            ip = ip.replace("profile_","")
            if tw_number:= self.db.get_timewindow_of_ts(ts):
                self.db.set_tw_label(ip, 'slips', tw_number, 'malicious')
                return True

        for alert in self.iterate('alerts'):
            # what we're doing here is marking tw 1 and 2 as malicious if a slips alert exists in parts of both
            #                      1:30                           2:30
            #                      │          slips alert          │
            #                      ├───────────────────────────────┤
            # 1:00                                 2:00                                  3:00
            # ├────────────────────────────────────┼─────────────────────────────────────┤
            # │             tw 1                   │            tw 2                     │

            for ts in (alert['tw_start'], alert['tw_end']):
                if not mark_tw_as_malicious(ts , alert['ip_alerted']):
                    # we can't get the corresponding tw of an alert that was found in slips,
                    # discard it and print a warning
                    self.warn_about_discarded_alert(alert)


    def parse_flow_by_flow_labels(self):
        """
        parses the labels set by slips flow by flow
        :return:
        """
        flows_count = 0
        for row in self.iterate('flows'):
            flows_count += 1
            # each row is a dict
            flow = {
                'aid': row['aid'],
                'label' : row['label']
            }
            if 'malicious' in row['label'].lower():
                self.malicious_labels += 1
                self.handle_labeling_tws(row)
            else:
                self.benign_labels += 1

            self.db.store_flow(flow, 'slips')
            # used for printing the stats in the main.py
            self.db.store_flows_count('slips', flows_count)

        self.log('', "-" * 30)

        self.log(f"Total malicious labels: ", self.malicious_labels)
        self.log(f"Total benign labels: ", self.benign_labels )
        self.log(f"Total Slips discarded timewindow labels (due to inability to map the ts to an existing tw): ", self.discarded_tw_labels)
        self.log('', "-" * 30)

        print()


    def parse(self):
        """reads the output db of slips with the labels and stores it in this tools' db"""
        # connect to the given db
        self.connect()
        self.parse_flow_by_flow_labels()
        self.parse_alerts_table()
