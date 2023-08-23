import os.path
import sqlite3
from threading import Lock
from time import sleep

class SQLiteDB():
    """Stores all the flows slips reads and handles labeling them"""
    _obj = None
    # used to lock each call to commit()
    cursor_lock = Lock()
    # stores each  type_ param supported value along with the name of the db
    # column that stores the label of this type_
    labels_map = {
        'slips': 'slips_label',
        'suricata': 'suricata_label',
        'ground_truth': 'ground_truth'
    }
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
            # this table will be used to store all the tools' labels per flow
            'flows': "community_id TEXT PRIMARY KEY, "
                     "ground_truth TEXT, "
                     "slips_label TEXT, "
                     "suricata_label TEXT",

            'flows_count': "type_ TEXT PRIMARY KEY, "
                           "count INT",

            # this table will be used to store all the tools' labels per timewindow, not flow by flow
            'labels_per_tw': "twid TEXT PRIMARY KEY, "
                             "start_date REAL, "
                             "end_date REAL, "
                             "ground_truth_label TEXT, "
                             "slips_label TEXT,  "
                             "suricata_label TEXT  ",

            # this reads the ts of all groundtruth flows, and has the cid and gt_label in common with the "flows" table
            'ground_truth_flows': "community_id TEXT PRIMARY KEY, "
                                  "flow_time REAL, "
                                  "ground_truth_label TEXT,  "
                                  "FOREIGN KEY (community_id) REFERENCES flows(community_id), "
                                  "FOREIGN KEY (ground_truth_label) REFERENCES flows(ground_truth)",

            # this reads the ts of all suricata flows, and has the cid and suricata_label in common with the "flows" table
            'suricata_flows': "community_id TEXT PRIMARY KEY, "
                              "flow_time REAL, "
                              "suricata_label TEXT,  "
                              "FOREIGN KEY (community_id) REFERENCES flows(community_id), "
                              "FOREIGN KEY (suricata_label) REFERENCES flows(suricata_label)",

            }
        for table_name, schema in table_schema.items():
            cls.create_table(table_name, schema)

    @classmethod
    def create_table(cls, table_name, schema):
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({schema})"
        cls.cursor.execute(query)
        cls.conn.commit()



    def print_table(self, table_name):
        """For debugging :D"""
        self.execute(f"SELECT * FROM {table_name}")
        rows = self.fetchall()

        # Print the table header
        column_names = [description[0] for description in self.cursor.description]
        print(column_names)

        # Print each row of the table
        for row in rows:
            print(row)

    def get_column_names(self, table: str) -> list:
        """
        returns a list of all column names in the given table
        """
        query = f"PRAGMA table_info({table})"
        self.execute(query)
        column_names = []
        for col in self.fetchall():
            column_names.append(col[1])
        return column_names


    def fill_null_labels(self):
        """
        iterates through all flows in the flows table, and filles the null labels with benign
        """

        for column in self.get_column_names('flows'):
            # fill all columns except the community id
            if column == 'community_id':
                continue

            query = f"UPDATE flows SET {column} = 'benign' WHERE {column} IS NULL"
            self.execute(query)

    def store_flows_count(self, type_: str, count: int):
        """
        store =s the total number of labeled flows by slips, suricata or ground_Truth
        :param type_:  slips, suricata or ground_truth
        :param count: number of labeled flows
        """
        query = f'INSERT INTO flows_count (type_, count) VALUES (\'{type_}\', {count});'
        self.execute(query)


    def store_flow(self, flow: dict, label_type: str):
        """
        updates or inserts into the flows db, the flow and label detected by the
        label_type (which is either slips or suricata)

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
            query = f'INSERT OR REPLACE INTO flows (community_id, {label_type}) VALUES (?, ?);'
            params = (community_id, label)
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

    def get_flows_count(self, type_:str, label="") -> int:
        """
        returns all the malicious/benign labeled flows by slips, suricata, or ground truth
        if type_ is 'slips' returns all the flows with slips_label = 'malicious'

        :param type_: can be 'slips' , 'suricata', or 'ground_truth'
        :param label: can be 'malicious' , 'benign'
        :return:
        """
        assert label in ['benign', 'malicious'], "get_malicious_flows_count() was given an invalid label"


        assert type_ in self.labels_map, "get_malicious_flows_count() was given an invalid type"

        column = self.labels_map[type_]
        return self.get_count('flows', condition=f'{column}="{label}"')

    def get_labeled_flows_by(self, type_):
        """
        returns a list with all flows that have a label by the given tool
         (by slips or suricata or a has a ground truth label)
        :param type_: can be 'slips' , 'suricata', or 'ground_truth'
        """
        assert type_ in self.labels_map, f'Trying to get labeled flows by invalid type: {type_}'

        # get the column name  of the given type
        label = self.labels_map[type_]

        query = f'SELECT * FROM flows WHERE {label} IS NOT NULL AND {label} != "";'
        self.execute(query)

        all_labeled_flows = self.fetchall()
        return all_labeled_flows


    def get_label_of_flow(self, community_id: str, by=None):
        """
        given a specific flow, returns the label by the given tool
        if by=None, returns all labels of this flow
        if by is given, the return value will either be 'benign', 'malicious' or None
        if not, it will be something like this
        ('1:AI5bDcB9qLc3eAAZ2Mle9Nb+DNs=', None, 'benign', None)
        :param by: can be 'slips' , 'suricata', or 'ground_truth'
        :return: 'malicious' or 'benign'
        """
        if not by:
            query = f'SELECT * FROM flows WHERE community_id = "{community_id}";'
        else:
            assert by in self.labels_map, f'trying to get the label set by an invalid tool {by}'
            label = self.labels_map[by]
            query = f'SELECT {label} FROM flows WHERE community_id = "{community_id}";'

        self.execute(query)
        label = self.fetchone()
        return label



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


