from utils.timewindow_handler import TimewindowHandler
from parsers.config import ConfigurationParser
from abstracts.dbs import IDB
from abstracts.observer import IObservable
from typing import Iterator, Optional
from math import ceil


class SQLiteDB(IDB, IObservable):
    """Stores all the flows slips reads and handles labeling them"""
    # stores the ts of the first flow for each tool
    ts_tracker = {}
    aid_collisions = 0
    discarded = 0

    def init(self):
        self.read_config()
        # column names use the current version of the tool read from config.yaml
        self.slips_label_col = f"slips_v{self.slips_version}_label"
        self.suricata_label_col = f"suricata_v{self.suricata_version}_label"
        self.labels_map = {
            'slips': self.slips_label_col,
            'suricata': self.suricata_label_col,
            'ground_truth': 'ground_truth_label'
        }
        if self.db_newly_created:
            # only init tables if the db is newly created
            self.init_tables()

    def read_config(self):
        config = ConfigurationParser('config.yaml')
        self.twid_width = config.timewindow_width()
        self.slips_version = config.slips_version().replace('.','')
        self.suricata_version = config.suricata_version().replace('.','')


    def init_tables(self):
        """creates the tables we're gonna use"""

        table_schema = {
            # this table will be used to store all the tools' labels per flow
            'labels_flow_by_flow': f"aid TEXT PRIMARY KEY, "
                                   f"ground_truth_label TEXT, "
                                   f"{self.slips_label_col} TEXT, "
                                   f"{self.suricata_label_col} TEXT",

            'flows_count': "type_ TEXT PRIMARY KEY, "
                           "count INT",

            # this reads the ts of all groundtruth flows, and has the aid and gt_label in common with the "flows" table
            'ground_truth_flows': "aid TEXT PRIMARY KEY, "
                                  "timestamp REAL, "
                                  "label TEXT,  "
                                  "FOREIGN KEY (aid) REFERENCES flows(aid), "
                                  "FOREIGN KEY (label) REFERENCES flows(ground_truth)",

            'performance_errors_flow_by_flow': "tool TEXT PRIMARY KEY, "
                                               "TP INTEGER, "
                                               "FP INTEGER, "
                                               "TN INTEGER, "
                                               "FN INTEGER",
            'discarded_flows': "tool TEXT PRIMARY KEY, "
                               "count INTEGER DEFAULT 0 ",

            'timewindow_details': "timewindow INTEGER PRIMARY KEY, "
                                  "start_time REAL, "
                                  "end_time REAL ",

            # this table will be used to store all the tools' labels per IP
            # per timewindow, not flow by flow
            # the combination of these 2 cols (IP, timewindow) are the
            # primary key, they have to be unique combined
            'labels_per_tw': f"IP TEXT NOT NULL, "
                             f"timewindow INTEGER NOT NULL, "
                             f"ground_truth_label TEXT, "
                             f"{self.slips_label_col} TEXT,  "
                             f"{self.suricata_label_col} TEXT,"
                             f"CONSTRAINT PK_interval PRIMARY KEY (IP, timewindow)",

            # there cannot be duplicate ip+tw+tool
            # this table stores the TP, tn FP fn per ip per tw per tool :D
            'performance_errors_per_tw': "tool TEXT PRIMARY KEY, "
                                         "TP INTEGER, "
                                         "FP INTEGER, "
                                         "TN INTEGER, "
                                         "FN INTEGER"

            }
        for table_name, schema in table_schema.items():
            self.create_table(table_name, schema)
        self.init_discarded_flows_table()


    def init_discarded_flows_table(self):
        # init the count of discarded_flows
        self.execute(f"INSERT INTO discarded_flows (tool, count) VALUES ('slips', 0)")
        self.execute(f"INSERT INTO discarded_flows (tool, count) VALUES ('suricata', 0)")

    def store_performance_errors_flow_by_flow(self, tool, metrics: dict):
        """
        stores the confusion matrix of each tool in performance_errors_flow_by_flow table
        :param tool: slips or suricata
        :param comparison_type: Per Timewindow or Flow By Flow
        :param metrics: dict with 'FP', 'FN', "TN", "TP"
        """
        query = f'INSERT OR REPLACE INTO performance_errors_flow_by_flow ' \
                f'(tool, TP, FP, TN, FN) ' \
                f'VALUES (?, ?, ?, ?, ?);'
        params = (tool, int(metrics['TP']), int(metrics['FP']), int(metrics['TN']), int(metrics['FN']))
        self.execute(query, params=params)

    def store_performance_errors_per_tw(self,  tool: str, cm: dict):
        """
        stores the performance errors of each tool in performance_errors_per_tw table
        :param tool: slips or suricata
        :param cm: dict with tp tn fp and fp. if a value is not there we store it in the db as 0
        """
        query = f"INSERT INTO performance_errors_per_tw " \
                f"(tool, TP, FP, TN, FN) " \
                f"VALUES (?, ?, ?, ?, ?)"
        params = (tool,
                  int(cm.get("TP", 0)),
                  int(cm.get("FP", 0)),
                  int(cm.get("TN", 0)),
                  int(cm.get("FN", 0)))
        self.execute(query, params=params)


    def get_flows_parsed(self, tool: str):
        """reads the number of flows parsed so far by tool from the flows_count table"""
        assert tool in ['suricata', 'ground_truth', 'slips']

        res = self.select('flows_count', '*', condition=f"type_ = '{tool}';", fetch='one')
        if res:
            return res[1]
        return 0

    def get_discarded_flows(self, tool: str):
        count = self.select('discarded_flows', '*',f" tool = '{tool}';", fetch='one')
        if count:
            return count[1]
        return 0

    def print_table(self, table_name):
        """For debugging :D"""
        rows = self.select(table_name, '*')

        # Print the table header
        column_names = [description[0] for description in self.cursor.description]
        print(column_names)

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
        iterates through all flows in the flows table, and fills the null labels with benign
        """
        for table in ('labels_flow_by_flow', 'labels_per_tw'):
            for column in self.get_column_names(table):
                # fill all columns except the community id
                if column in ('aid', 'IP', 'timewindow', ''):
                    continue

                query = f"UPDATE {table} SET {column} = 'benign' WHERE {column} IS NULL"
                self.execute(query)



    def increase_discarded_flows(self, tool: str):
        """
        increments the number of discarded flows by a tool by 1
        flows are discarded when they're found in a tool but not in the ground truth
        """
        query = f"UPDATE discarded_flows SET count = count + 1 WHERE tool = '{tool}';"
        self.execute(query)

    def store_flows_count(self, tool: str, count: int):
        """
        store =s the total number of labeled flows by slips, suricata or ground_Truth
        :param tool:  slips, suricata or ground_truth
        :param count: number of labeled flows
        """
        query = f'INSERT OR REPLACE INTO flows_count (type_, count) VALUES (\'{tool}\', {count});'
        self.execute(query)


    def store_flow(self, flow: dict, tool: str):
        """
        updates or inserts into the labels_flow_by_flow table,
        the flow and label detected by the
        label_type (which is either slips or suricata)

        :param flow: dict with aid and label
        :param tool: the label can be the ground_truth , slips, or suricata
        :return: True if the flow is stored in the db and False if it is discarded
        """
        aid = flow["aid"]
        label = flow['label']

        # check if the row already exists with a label
        exists = self.select('labels_flow_by_flow', '*', condition=f'aid="{aid}"')
        if tool == 'ground_truth':
            label_col: str = self.labels_map[tool]
            if exists:
                # aid collision in gt, replace the old flow
                # TODO handle this
                print(f"[Warning] Found collision in ground truth. 2 flows have the same aid."
                      f" flow: {flow}. label_type: {tool} .. "
                      f"discarded the first flow and stored the last one only.")
                self.aid_collisions += 1
                self.update('labels_flow_by_flow', f'{label_col}= "{label}"', condition=f'aid ="{aid}"')
            else:
                query = f'INSERT INTO labels_flow_by_flow (aid, {label_col}) VALUES (?, ?);'
                params = (aid, label)
                self.execute(query, params=params)
        else:
            # this flow is read by a tool, not the gt
            # if the gt doesn't have the aid of this flow, we discard it
            if exists:
                # this flow is read by slips or suricata AND was read by one of them or the gt before
                # now we update this flow's label to the latest label seen in the eve.json or the slips db
                # TODO write this in the docs

                # we have this problem of suricata logging the same flow many times, sometimes in an alert event,
                # other times as a flow event
                # the solution to this is, if a fow was found once as malicious, we don't change its' label
                # to benign again. event if it was found many times as a "flow" event
                # TODO write this in the docs
                flow_old_label: Optional[str] = self.get_label_of_flow(aid, by=tool)
                if flow_old_label == 'malicious':
                    return True

                # can be slips_vxxx_label or suricata_vxxx_label
                label_col: str = self.labels_map[tool]
                query = f"UPDATE labels_flow_by_flow SET {label_col} = \"{label}\" WHERE aid = \"{aid}\";"
                self.execute(query)
            else:
                self.increase_discarded_flows(tool)
                return False
        return True

    def get_aid_collisions(self):
        return self.aid_collisions


    def store_ground_truth_flow(self, flow: dict):
        """
        fills the ground_truth_flows table with the gt flow read from the zeek log
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
        row = self.select(f"{tool}_flows", 'MIN(timestamp)', fetch='one')
        return float(row[0])


    def get_last_ts(self, tool: str):
        """
        returns the max ts stored by the given tool
        :param tool: suricata or ground_truth
        :return: ts
        """
        row = self.select('MAX(timestamp)', f"{tool}_flows", fetch='one')
        return float(row[0])


    def register_tw(self, tw: int, tw_start_ts: float, tw_end_ts: float) -> \
            bool:
        """
        calculates the end ts of the given timewindow and stores in the
         timewindow_details table
        :param tw_start_ts: the timestamp of the start of the given timewindow
        :param tw: number of the tw to set the timestamps to
        :param tw_end_ts: the timestamp of the end of this timewindow
        """
        if self.is_registered_timewindow(tw):
            return False

        query = f'INSERT INTO timewindow_details ' \
                f'(timewindow, start_time, end_time) VALUES (?, ?, ?);'
        params = (tw, tw_start_ts, tw_end_ts)
        self.execute(query, params=params)
        return True


    def get_first_row(self, table: str):
        query = f'SELECT * FROM {table} LIMIT 1'
        self.execute(query)
        return self.fetchone()

    def get_last_row(self, table: str):
        query = f'SELECT * FROM {table} ORDER BY ROWID DESC LIMIT 1'
        self.execute(query)
        return self.fetchone()

    def get_timewindows_limit(self):
        """
        returns the period of time that the ground truth knows about and has
        flows and labels for
        :return: (the start timestamp of the first timewindow,  the end timestamp of the last timewindow)
        """
        start_time: dict = self.get_first_row('timewindow_details')[1]
        end_time: str = self.get_last_row('timewindow_details')[2]

        return (start_time, end_time)


    def get_timewindow_of_ts(self, ts: float) -> int:
        """
        returns the timewindow in which the given timestamp belongs to
        :param ts: float unix timestamp
        :param tool: options are slips, suricata, or ground_truth
        :return: the timewindow number
        """
        # todo should be moved to twid handler
        condition = f"{ts} >= start_time AND {ts} <= end_time "
        results: list = self.select('timewindow_details',
                                    'timewindow',
                                    condition=condition)
        if results:
            # tw was seen before and is there in the db
            return int(results[0][0])

        # timewindow was not seen by the gt
        # calc it manually
        starttime_of_first_timewindow: float = self.select(
            'timewindow_details',
            'start_time',
            condition=f"timewindow = 0",
            fetch='one')[0]
        if ts < starttime_of_first_timewindow:
            # negative timewindow
            tw = ceil((ts - starttime_of_first_timewindow) /self.twid_width) - 1
        elif ts == starttime_of_first_timewindow:
            tw = 0
        else:
            # positive tw
            tw = int((ts - starttime_of_first_timewindow)/self.twid_width)

        return tw


    def set_tw_label(self, ip: str, tool: str, tw: int, label: str):
        """
        fills the labels_per_tw table with each tw and the label of it for the given tool
        :param label: malicious or benign
        """
        if tool not in ['suricata', 'ground_truth', 'slips']:
            print("TRYING TO STORE THE LABEL FOR AN INVALID TOOL!!")
            return False

        label_col:str = self.labels_map[tool]
        query = f'INSERT OR REPLACE INTO labels_per_tw (IP, timewindow, {label_col}) VALUES (?, ?, ?);'
        params = (ip, tw, label)
        self.execute(query, params=params)

        # set the gt label of this tw as benign if it wasn't found
        query = f"UPDATE labels_per_tw SET ground_truth_label = 'benign' " \
                f"WHERE ground_truth_label IS NULL " \
                f"AND IP = '{ip}' " \
                f"AND timewindow = '{tw}'"
        self.execute(query)

    def get_last_registered_timewindow(self) -> int:
        """
        returns the last timewindow read by the ground truth from the labels_per_tw table
        :return: timewindow number
        """
        tw = self.select('labels_per_tw', 'MAX(timewindow)', fetch='one')
        return int(tw[0])


    def is_registered_timewindow(self, tw: int) -> bool:
        """
        checks if the tw is registered in the timewindow_details table
        :param tw: int
        """
        res = self.select(
            "timewindow_details",
            "*",
            condition=f"timewindow={tw}",
            fetch="one"
            )
        return True if res else False


    def get_all_labels_per_all_tws(self, tool: str) -> Iterator[str]:
        """
        GT labels and all tools' labels are stored in the labels_per_tw table

        this method returns an iterator that iterates through all the rows in
         the labels_per_tw table
        and returns the GT label + the given tool's label along with the IP and tw
        :param tool: slips or suricata
        :return: reurns an iterator that iterates through all rows by
        the given tool in the labels_per_Tw table
        return value looks like this
        [(IP, tw, gt_label, tool_label),(..),(..)]
        """
        label_col = self.labels_map[tool]
        cols = f'IP, timewindow, ground_truth_label, {label_col}'

        # IMPORTANT: don't use select() here, we'll fetch one by one
        self.execute(f"SELECT {cols} from labels_per_tw ")

        while True:
            row = self.fetchone()
            if row is None:
                break
            yield row


    def get_labels_flow_by_flow(self, by='all') -> Iterator[str]:
        """
        yields actual and predicted labels from the labels_flow_by_flow table
        :param by: do we want the labels for all tools? slips only? or suricata only?
        """
        if by == 'all':
            cols = '*'
        else:
            label_col = self.labels_map[by]
            cols = f'ground_truth_label, {label_col}'

        # don't use select() here, we'll fetch one by one
        self.execute(f"SELECT {cols} from labels_flow_by_flow")

        while True:
            row = self.fetchone()
            if row is None:
                break
            yield row

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
        res = self.select(table_name,
                    '*',
                    f"timestamp >= {tw_start} "
                    f"AND timestamp <= {tw_end} "
                    f"AND label = 'malicious';")
        return True if res else False


    def get_flows_count(self, type_:str, label="") -> int:
        """
        returns all the malicious/benign labeled flows by slips, suricata, or ground truth from the
        labels_flow_by_flow timewindow
        if type_ is 'slips' returns all the flows with slips_label = 'malicious'

        :param type_: can be 'slips' , 'suricata', or 'ground_truth'
        :param label: can be 'malicious' , 'benign'
        :return:
        """
        assert label in ['benign', 'malicious'], "get_malicious_flows_count() was given an invalid label"

        assert type_ in self.labels_map, "get_malicious_flows_count() was given an invalid type"

        column = self.labels_map[type_]
        return self.get_count('labels_flow_by_flow', condition=f'{column}="{label}"')


    def get_labeled_flows_by(self, type_):
        """
        returns a list with all flows that have a label by the given tool
         (by slips or suricata or a has a ground truth label)
        :param type_: can be 'slips' , 'suricata', or 'ground_truth'
        """
        assert type_ in self.labels_map, f'Trying to get labeled flows by invalid type: {type_}'

        # get the column name  of the given type
        label = self.labels_map[type_]

        all_labeled_flows = self.select('labels_flow_by_flow', '*', condition=f' {label} IS NOT NULL AND {label} != "";')
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
            return self.select('labels_flow_by_flow', '*', condition=f' aid = "{aid}";', fetch='one')

        assert by in self.labels_map, f'trying to get the label set by an invalid tool {by}'
        label_col = self.labels_map[by]
        return self.select('labels_flow_by_flow', label_col, condition=f' aid = "{aid}";', fetch='one')[0]





