from utils.timewindow_handler import TimewindowHandler
from parsers.config import ConfigurationParser
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
    # stores the ts of the first flow for each tool
    ts_tracker = {}
    aid_collisions = 0

    def __init__(self, output_dir):
        super(SQLiteDB, self).__new__(SQLiteDB)
        self._flows_db = os.path.join(output_dir, 'db.sqlite')
        self.connect()
        self.read_config()

    def read_config(self):
        config = ConfigurationParser('config.yaml')
        self.twid_width = config.timewindow_width()

    def connect(self):
        """
        Creates the db if it doesn't exist and connects to it
        """
        db_newly_created = False
        if not os.path.exists(self._flows_db):
            # db not created, mark it as first time accessing it so we can init tables once we connect
            db_newly_created = True
            self._init_db()

        self.conn = sqlite3.connect(self._flows_db, check_same_thread=False)

        self.cursor = self.conn.cursor()
        if db_newly_created:
            # only init tables if the db is newly created
            self.init_tables()


    def _init_db(self):
        """
        creates the db if it doesn't exist and clears it if it exists
        """
        open(self._flows_db,'w').close()

    def init_tables(self):
        """creates the tables we're gonna use"""
        table_schema = {
            # this table will be used to store all the tools' labels per flow
            'flows': "aid TEXT PRIMARY KEY, "
                     "ground_truth TEXT, "
                     "slips_label TEXT, "
                     "suricata_label TEXT",

            'flows_count': "type_ TEXT PRIMARY KEY, "
                           "count INT",

            # this reads the ts of all groundtruth flows, and has the aid and gt_label in common with the "flows" table
            'ground_truth_flows': "aid TEXT PRIMARY KEY, "
                                  "timestamp REAL, "
                                  "label TEXT,  "
                                  "FOREIGN KEY (aid) REFERENCES flows(aid), "
                                  "FOREIGN KEY (label) REFERENCES flows(ground_truth)",

            # this reads the ts of all suricata flows, and has the aid and suricata_label in common with the "flows" table
            'suricata_flows': "aid TEXT PRIMARY KEY, "
                              "timestamp REAL, "
                              "label TEXT,  "
                              "FOREIGN KEY (aid) REFERENCES flows(aid), "
                              "FOREIGN KEY (label) REFERENCES flows(suricata_label)",
            'performance_errors': "tool TEXT, "
                                  "TP INTEGER, "
                                  "FP INTEGER, "
                                  "TN INTEGER, "
                                  "FN INTEGER",
            'discarded_flows': "tool TEXT, "
                               "count INTEGER DEFAULT 0 ",

            'timewindow_details': "timewindow INTEGER PRIMARY KEY, "
                                  "start_time REAL, "
                                  "end_time REAL ",

            # this table will be used to store all the tools' labels per IP per timewindow, not flow by flow
            # the combination of these 2 cols (IP, timewindow) are the primary key, they have to be unique combined
            'labels_per_tw': "IP TEXT NOT NULL, "
                             "timewindow TEXT NOT NULL, "
                             "ground_truth_label TEXT, "
                             "slips_label TEXT,  "
                             "suricata_label TEXT,"
                             "CONSTRAINT PK_interval PRIMARY KEY (IP, timewindow)",

            }
        for table_name, schema in table_schema.items():
            self.create_table(table_name, schema)
        self.init_discarded_flows_table()


    def create_table(self, table_name, schema):
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({schema})"
        self.cursor.execute(query)
        self.conn.commit()

    def init_discarded_flows_table(self):
        # init the count of discarded_flows
        self.execute(f"INSERT INTO discarded_flows (tool, count) VALUES ('slips', 0)")
        self.execute(f"INSERT INTO discarded_flows (tool, count) VALUES ('suricata', 0)")

    def store_confusion_matrix(self, tool, metrics: dict):
        """
        stores the confusion matrix of each tool in performance_errors table
        :param tool: slips or suricata
        :param metrics: dict with 'FP', 'FN', "TN", "TP"
        """
        query = f'INSERT OR REPLACE INTO performance_errors (tool, TP, FP, TN, FN) VALUES (?, ?, ?, ?, ?);'
        params = (tool, int(metrics['TP']),int(metrics['FP']), int(metrics['TN']), int(metrics['FN']))
        self.execute(query, params=params)

    def get_flows_parsed(self, tool: str):
        """reads the number of flows parsed so far by tool from the flows_count table"""
        assert tool in ['suricata', 'ground_truth', 'slips']

        query = f"SELECT * FROM flows_count where type_ = '{tool}';"
        self.execute(query)

        if count:= self.fetchone():
            return count[1]
        return 0

    def get_discarded_flows(self, tool: str):
        query = f"SELECT * FROM discarded_flows where tool = '{tool}';"
        self.execute(query)

        if count:= self.fetchone():
            return count[1]
        return 0

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
            if column == 'aid':
                continue

            query = f"UPDATE flows SET {column} = 'benign' WHERE {column} IS NULL"
            self.execute(query)

    def increase_discarded_flows(self, tool: str):
        """
        increments the number of discarded flows by a tool by 1
        flows are discarded when they're found in a tool but not in the ground truth
        """
        query = f"UPDATE discarded_flows SET count = count + 1 WHERE tool = '{tool}';"
        self.execute(query)

    def store_flows_count(self, type_: str, count: int):
        """
        store =s the total number of labeled flows by slips, suricata or ground_Truth
        :param type_:  slips, suricata or ground_truth
        :param count: number of labeled flows
        """
        query = f'INSERT OR REPLACE INTO flows_count (type_, count) VALUES (\'{type_}\', {count});'
        self.execute(query)


    def store_flow(self, flow: dict, label_type: str):
        """
        updates or inserts into the flows db, the flow and label detected by the
        label_type (which is either slips or suricata)

        :param flow: dict with aid and label
        :param label_type: the label can be the ground_truth , slips_label, or suricata_label
        """
        aid = flow["aid"]
        label = flow['label']

        # check if the row already exists with a label
        exists = self.select('flows', '*', condition=f'aid="{aid}"')
        if label_type == 'ground_truth':
            if exists:
                # aid collision in gt, replace the old flow
                # #TODO handle this
                print(f"[Warning] Found collision in ground truth. 2 flows have the same aid."
                      f" flow: {flow}. label_type: {label_type} .. "
                      f"discarded the first flow and stored the last one only.")
                self.aid_collisions += 1
                self.update('flows', f'{label_type}= "{label}"', condition=f'aid ="{aid}"')
            else:
                query = f'INSERT INTO flows (aid, {label_type}) VALUES (?, ?);'
                params = (aid, label)
                self.execute(query, params=params)
        else:
            # this flow is read by a tool, not the gt
            # if the gt doesn't have the aid of this flow, we discard it
            if exists:
                query = f"UPDATE flows SET {label_type} = \"{label}\" WHERE aid = \"{aid}\";"
                self.execute(query)

            else:
                tool = label_type.replace("_label",'')
                self.increase_discarded_flows(tool)
                return

    def get_aid_collisions(self):
        return self.aid_collisions

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

    def store_suricata_flow_ts(self, flow: dict):
        """
        fills the suricata_flows table with the suricata flow read from eve.json
        :param flow: contains timestamp, aid and label of the flow
        """
        query = f'INSERT OR REPLACE INTO suricata_flows (aid, timestamp, label) VALUES (?, ?, ?);'
        params = (flow['aid'], flow['timestamp'], flow['label'])
        self.execute(query, params=params)

    def store_ground_truth_flow_ts(self, flow: dict):
        """
        fills the ground_truth_flows table with the suricata flow read from eve.json
        :param flow: contains timestamp(in unix format), aid and label of the flow
        """
        query = f'INSERT OR REPLACE INTO ground_truth_flows (aid, timestamp, label) VALUES (?, ?, ?);'
        params = (flow['aid'], flow['timestamp'], flow['label'])
        self.execute(query, params=params)

    def get_first_ts(self, tool: str):
        """
        returns the least ts of the given tool
        :param tool: suricata or ground_truth
        :return: ts
        """
        query = f'select MIN(timestamp) FROM {tool}_flows ;'
        self.execute(query)
        row = self.fetchone()
        return float(row[0])

    def get_last_ts(self, tool: str):
        """
        returns the max ts stored by the given tool
        :param tool: suricata or ground_truth
        :return: ts
        """
        query = f'select MAX(timestamp) FROM {tool}_flows ;'
        self.execute(query)
        row = self.fetchone()
        return float(row[0])


    def set_ts_of_tw(self, tw: int, tw_start_ts: float) -> float:
        """
        calculates the end ts of the given timewindow
        and fills the timewindow_details table with the start and end time of it
        :param tw_start_ts: the timestamp of the start of the given timewindow
        :param tw: number of the tw to set the timestamps to
        :return: the timestamp of the end of this timewindow
        """

        tw_end_ts = tw_start_ts + self.twid_width
        query = f'INSERT INTO timewindow_details (timewindow, start_time, end_time) VALUES (?, ?, ?);'
        params = (tw, tw_start_ts, tw_end_ts)
        self.execute(query, params=params)

        return tw_end_ts


    def get_timewindow_of_ts(self, ts: float) -> int:
        """
        returns the timewindow in which the given timestamp belongs to
        :param ts: float unix timestamp
        :return: the timewindow number
        """
        #todo convert all the select queries to methdod

        results: list = self.select('timewindow_details', 'timewindow', condition=f"{ts} >= start_time AND {ts} <= end_time ")
        if results:
            return int(results[0][0])

        # handle not found tw!
        #TODO

    def set_tw_label(self, ip: str, tool: str, tw: int, label: str):
        """
        fills the labels_per_tw table with each tw and the label of it for the given tool
        :param label: malicious or benign
        """
        if tool not in ['suricata', 'ground_truth', 'slips']:
            print("TRYING TO STORE THE LABEL FOR AN INVALID TOOL!!")
            return False

        label_col = f"{tool}_label"
        query = f'INSERT OR REPLACE INTO labels_per_tw (IP, timewindow, {label_col}) VALUES (?, ?, ?);'
        params = (ip, tw, label)
        self.execute(query, params=params)


    def is_tw_marked_as_malicious(self, tool: str, twid: int) -> bool:
        """
        checks all the flows in a given twid and marks the tw as malicious if there's 1 malicious flow in this twid
        tool can't be slips because it doesn't have the ts and labels in slips_flows like rest
        slips parser will handle checking the malicious tws in slips
        :param tool: ground_truth or suricata
        :param twid: 1 or 2 or 3
        :return: bool
        """
        if tool not in ['suricata', 'ground_truth']:
            return False

        # only get the first ts once
        if tool not in self.ts_tracker:
            self.ts_tracker[tool] = self.get_first_ts(tool)

        twid_handler = TimewindowHandler(self.ts_tracker[tool])
        tw_start, tw_end = twid_handler.get_start_and_end_ts(twid)

        table_name = f"{tool}_flows"
        query = f"SELECT * FROM {table_name} WHERE " \
                f"timestamp >= {tw_start} " \
                f"AND timestamp <= {tw_end} " \
                f"AND label = 'malicious';"
        self.execute(query)

        return True if self.fetchall() else False


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


    def get_label_of_flow(self, aid: str, by=None):
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
            query = f'SELECT * FROM flows WHERE aid = "{aid}";'
        else:
            assert by in self.labels_map, f'trying to get the label set by an invalid tool {by}'
            label = self.labels_map[by]
            query = f'SELECT {label} FROM flows WHERE aid = "{aid}";'

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


