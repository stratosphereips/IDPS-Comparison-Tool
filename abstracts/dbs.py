from abc import abstractmethod, ABC
import sqlite3
from os import path
from time import sleep
from threading import Lock
from termcolor import colored
from abstracts.observer import IObservable
from logger.logger import Logger

class IDB(IObservable, ABC ):
    """
    Interface for every sqlite db
    """
    name = ''
    # used to lock each call to commit()
    cursor_lock = Lock()
    db_newly_created = False

    def __init__(
            self,
            output_dir=None,
            db_full_path=None,
         ):
        """
        :param output_dir: output dir. when this param is given a new db is created in this output dir
        :param db_path: full path to the db to connect to
        """
        self.output_dir = output_dir
        self.path: str = db_full_path

        IObservable.__init__(self)
        self.logger = Logger(self.name, self.output_dir)
        # add the logger as an observer so each msg printed to the cli will be sent to it too
        self.add_observer(self.logger)

        self.connect()
        self.init()

    def log(self, green_txt, normal_txt, log_to_results_file=True, end="\n"):
        """
        gives the txt to the logger to log it to stdout and results.txt
        """
        self.notify_observers((normal_txt, green_txt, log_to_results_file, end))


    def connect(self):
        """
        Creates the db if it doesn't exist and connects to it
        sets the db_newly_created to True if the db didn't already exist
        """
        if self.path:
            if not path.exists(self.path):
                raise(f"Invalid databse path: {self.path}")
        elif self.output_dir:
            self.path = path.join(self.output_dir, 'db.sqlite')
            if not path.exists(self.path):
                # db not created, mark it as first time accessing it
                # so we can init tables once we connect
                self.db_newly_created = True
                open(self.path,'w').close()

        self.conn = sqlite3.connect(
            self.path,
            check_same_thread=False)

        self.cursor = self.conn.cursor()

    @abstractmethod
    def init(self):
        """"""


    def create_table(self, table_name, schema):
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({schema})"
        self.cursor.execute(query)
        self.conn.commit()


    def get_count(self, table, condition=None):
        """
        returns the number of matching rows in the given table based on a specific contioins
        """
        res = self.select(table, 'COUNT(*)', condition=condition, fetch='one')
        return res[0]


    def close(self):
        self.cursor.close()
        self.conn.close()

    def fetchall(self):
        """
        wrapper for sqlite fetchall to be able to use a lock
        """
        self.cursor_lock.acquire(True)
        res = self.cursor.fetchall()
        self.cursor_lock.release()
        return res


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
            #start a transaction
            self.cursor.execute('BEGIN')

            if not params:
                self.cursor.execute(query)
            else:
                self.cursor.execute(query, params)

            self.conn.commit()

            self.cursor_lock.release()
        except sqlite3.Error as e:
            # An error occurred during execution
            self.conn.rollback()

            if "database is locked" in str(e):
                self.cursor_lock.release()
                # Retry after a short delay
                sleep(0.1)
                self.execute(query, params=params)
            else:
                # An error occurred during execution
                print(f"Error executing query ({query}): {e} - params: {params}")


    def select(self, table_name, columns="*", condition=None, fetch='all'):
        query = f"SELECT {columns} FROM {table_name}"
        if condition:
            query += f" WHERE {condition}"
        self.execute(query)
        if fetch == 'all':
            result = self.fetchall()
        else:
            result = self.fetchone()
        return result


    def insert(self, table_name, values):
        query = f"INSERT INTO {table_name} VALUES ({values})"
        self.execute(query)


    def update(self, table_name, set_clause, condition):
        query = f"UPDATE {table_name} SET {set_clause} WHERE {condition}"
        self.execute(query)


    def delete(self, table_name, condition):
        query = f"DELETE FROM {table_name} WHERE {condition}"
        self.execute(query)

