from utils.timewindow_handler import TimewindowHandler
from utils.timestamp_handler import TimestampHandler
from utils.hash import Hash
from abstracts.abstracts import Parser
from database.sqlite_db import SQLiteDB

import json


class SuricataParser(Parser):
    name = "SuricataParser"
    def init(self,
             eve_file=None):
        self.eve_file: str = eve_file
        # to be able to get the ts of the first flow
        self.is_first_flow = True
        self.hash = Hash()
        self.time = TimestampHandler()

    def extract_flow(self, line: str) -> dict:
        """
        extracts the src/dst addr/port from normal flows
        or icmp type and code from icmp flows from the given line
        :param line: suricata line as read from the file
        """
        proto = line['proto'].lower()
        flow = {
            'timestamp':  line['flow']['start'],
            'saddr': line['src_ip'],
            'daddr': line['dest_ip'],
            'proto': proto,
        }

        if 'icmp' in proto:
            flow.update({
                'type': line['icmp_type'],
                'code': line['icmp_code'],
            })
        else:
            flow.update({
                'sport': line['src_port'],
                'dport': line['dest_port'],
            })

        return flow

    def handle_labeling_tws(self):
        """
        checks the label for each tw and stores the tw and the label in the db
        """
        last_ts = self.db.get_last_ts('suricata')

        last_available_tw: int = self.twid_handler.get_tw_of_ts(last_ts)
        # print(f"@@@@@@@@@@@@@@@@ suricata: last_ts {last_ts} last_available_tw: {last_available_tw}")

        for tw in range(last_available_tw+1):
            if self.db.is_tw_marked_as_malicious('suricata', tw):
                label = 'malicious'
            else:
                label = 'benign'
            # print(f"@@@@@@@@@@@@@@@@ suricata tw: {tw} is marked as {label}")
            self.db.store_tw_label('suricata', tw, label)

    def parse(self):
        """reads the given suricata eve.json"""
        with open(self.eve_file, 'r') as f:
            flows_count = 0
            while line := f.readline():
                line = json.loads(line)
                event_type = line['event_type']

                if event_type == 'stats':
                    continue

                flows_count += 1

                flow: dict = self.extract_flow(line)

                timestamp = self.time.convert_iso_8601_to_unix_timestamp(flow['timestamp'])
                flow['timestamp'] = timestamp
                # start the tw handler and keep track of the ts of the first tw
                if self.is_first_flow:
                    self.twid_handler = TimewindowHandler(ts_of_first_flow=timestamp)
                    self.is_first_flow = False

                #TODO suricata calculates the aid in a wrong way, we'll be calculating it on the fly until they fix it
                aid: str = self.hash.get_aid(flow)
                # todo we assume all flows with event_type=alert are marked as malicious by suricata
                label =  'malicious' if line['event_type'] == 'alert' else 'benign'

                flow = {
                    'aid' : aid,
                    'label' : label,
                    'timestamp': timestamp
                    }

                self.db.store_flow(
                    flow,
                    'suricata_label'
                )
                self.db.store_suricata_flow_ts(flow)

                # used for printing the stats in the main.py
                self.db.store_flows_count('suricata', flows_count)

            self.handle_labeling_tws()



