from utils import get_community_id, convert_iso_8601_to_unix_timestamp, TimewindowHandler
from database.sqlite_db import SQLiteDB
from termcolor import colored
import json


class SuricataParser:
    name = "SuricataParser"
    def __init__(self, eve_file: str, db: SQLiteDB):
        self.eve_file: str = eve_file
        self.db = db
        # to be able to get the ts of the first flow
        self.is_first_flow = True

    def log(self, green_txt, normal_txt):
        normal_txt = str(normal_txt)
        green_txt = str(green_txt)

        print(colored(f'[{self.name}] ', 'blue') + colored(green_txt,'green') + normal_txt)

    def extract_flow(self, line: str) -> dict:
        """
        extracts the src/dst addr/port from normal flows
        or icmp type and code from icmp flows from the given line
        :param line: suricata line as read from the file
        """
        proto = line['proto'].lower()
        flow = {
            'timestamp': line['timestamp'],
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

    def parse(self):
        """reads the given suricata eve.json"""
        with open(self.eve_file, 'r') as f:
            flows = 0
            while line := f.readline():
                line = json.loads(line)
                event_type = line['event_type']
                flows += 1



                if event_type == 'stats':
                    continue

                flow: dict = self.extract_flow(line)
                timestamp = convert_iso_8601_to_unix_timestamp(flow['timestamp'])

                # start the tw handler and keep track of the ts of the first tw
                if self.is_first_flow:
                    self.twid_handler = TimewindowHandler(ts_of_first_flow=timestamp)
                    self.is_first_flow = False

                #TODO suricata calculates the cid in a wrong way, we'll be calculating it on the fly until they fix it
                cid: str = get_community_id(flow)

                # todo we assume all flows with event_type=alert are marked as malicious by suricata
                label =  'malicious' if line['event_type'] == 'alert' else 'benign'

                flow = {
                    'community_id' : cid,
                    'label' : label
                }

                self.db.store_flow(flow, 'suricata_label')
                flow.update({'timestamp': timestamp})
                self.db.store_suricata_flow_ts(flow)
                self.log(f"Extracted suricata label for flow: ", cid)

            # store the number of flows read from the suricata logfile
            self.db.store_flows_count('suricata', flows)


