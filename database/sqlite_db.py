import os.path
import sqlite3
from threading import Lock
from time import sleep

class SQLiteDB():
    """Stores all the flows slips reads and handles labeling them"""
    _obj = None
    # used to lock each call to commit()
    cursor_lock = Lock()

    def __new__(cls, output_dir):
        # To treat the db as a singelton
        if cls._obj is None or not isinstance(cls._obj, cls):
            cls._obj = super(SQLiteDB, cls).__new__(SQLiteDB)
            # db for storing the current labels
            cls._flows_db = os.path.join(output_dir, 'db.sqlite')
            cls._init_db()
            cls.conn = sqlite3.connect(cls._flows_db, check_same_thread=False)
            cls.cursor = cls.conn.cursor()
            cls.init_tables()
        return cls._obj


    @classmethod
    def _init_db(cls):
        """
        creates the db if it doesn't exist and clears it if it exists
        """
        open(cls._flows_db,'w').close()

    @classmethod
    def init_tables(cls):
        """creates the tables we're gonna use"""
        table_schema = {
            'flows': "community_id TEXT PRIMARY KEY, ground_truth TEXT, slips_label TEXT, suricata_label TEXT",
            }
        for table_name, schema in table_schema.items():
            cls.create_table(table_name, schema)

    @classmethod
    def create_table(cls, table_name, schema):
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({schema})"
        cls.cursor.execute(query)
        cls.conn.commit()


    def store_flow(self, flow: dict, label_type: str):
        """
        :param flow: dict with community_id and label
        :param label_type: the label can be the ground_truth , slips_label, or suricata_label
        """
        community_id = flow["community_id"]
        label = flow['label']

        # check if the row already exists with a label
        exists = self.select('flows', '*', condition=f'community_id="{community_id}"')

        if exists:
            self.update('flows', f'{label_type}= "{label}"', condition=f'community_id ="{community_id}"')
        else:
            params = (community_id, label)
            query = f'INSERT OR REPLACE INTO flows (community_id, {label_type}) VALUES (?, ?);'
            self.execute(query, params=params)


    def insert(self, table_name, values):
        query = f"INSERT INTO {table_name} VALUES ({values})"
        self.execute(query)


    def update(self, table_name, set_clause, condition):
        query = f"UPDATE {table_name} SET {set_clause} WHERE {condition}"
        self.execute(query)


    def delete(self, table_name, condition):
        query = f"DELETE FROM {table_name} WHERE {condition}"
        self.execute(query)


    def select(self, table_name, columns="*", condition=None):
        query = f"SELECT {columns} FROM {table_name}"
        if condition:
            query += f" WHERE {condition}"
        self.execute(query)
        result = self.fetchall()
        return result


    def get_malicious_flows_count(self, type_) -> int:
        """
        returns all the malicious labeled flows by slips, suricata, or ground truth
        if type_ is 'slips' returns all the flows with slips_label = 'malicious'

        :param type_: can be 'slips' , 'suricata', or 'ground_truth'
        :return:
        """
        # stores each  type_ param supported value along with the name of the db
        # column that stores the label of this type_
        map = {
            'slips': 'slips_label',
            'suricata': 'suricata_label',
            'ground_truth': 'ground_truth'
        }
        assert type_ in map, "get_malicious_flows_count() was given an invalid type"
        column = map[type_]
        return self.get_count('flows', condition=f'{column}="malicious"')

    def get_count(self, table, condition=None):
        """
        returns the number of matching rows in the given table based on a specific contioins
        """
        query = f"SELECT COUNT(*) FROM {table}"

        if condition:
            query += f" WHERE {condition}"

        self.execute(query)
        return self.fetchone()[0]


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


