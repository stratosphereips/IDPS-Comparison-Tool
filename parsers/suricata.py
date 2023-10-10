from utils.timestamp_handler import TimestampHandler
from parsers.config import ConfigurationParser
from utils.hash import Hash
from abstracts.parsers import Parser

import json


class SuricataParser(Parser):
    name = "SuricataParser"

    def init(self,
             eve_file=None):
        self.eve_file: str = eve_file
        # to be able to get the ts of the first flow
        self.is_first_flow = True
        self.hash = Hash()
        self.timestamp_handler = TimestampHandler()
        self.read_config()
        self.tw_start = self.db.get_timewindows_limit()[0]
        self.tw_end = self.tw_start + self.twid_width


    def read_config(self):
        config = ConfigurationParser('config.yaml')
        self.twid_width = float(config.timewindow_width())

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

    def label_tw(self, ts: float, srcip: str, label: str):
        """
        sets the label of the twid where the given ts exists as malicious by suricata
        :param ts: current flow timestamp
        :param label: malicious or benign
        :return:
        """
        # if 1 flow is malicious, mark the whole tw as malicious by suricata
        # map this suricata flow to one of the existing(gt) timewindows
        if tw := self.db.get_timewindow_of_ts(ts):
            self.db.set_tw_label(srcip, 'suricata', tw, label)
            return True


    def print_stats(self):
        self.log('', "-" * 30)
        self.log(f"Total malicious labels: ", self.db.get_flows_count('suricata', 'malicious'))
        self.log(f"Total benign labels: ", self.db.get_flows_count('suricata', 'benign'))
        self.log('', "-" * 30)

        print()


    def parse(self):
        """reads the given suricata eve.json"""
        with open(self.eve_file, 'r') as f:
            flows_count = 0
            while line := f.readline():
                line = json.loads(line)
                event_type = line['event_type']

                if event_type not in ('flow', 'alert'):
                    # only read benign flows and alert events
                    continue


                flow: dict = self.extract_flow(line)
                original_ts = flow['timestamp']
                timestamp = self.timestamp_handler.convert_iso_8601_to_unix_timestamp(flow['timestamp'])
                flow['timestamp'] = timestamp

                # suricata calculates the aid in a wrong way, we'll be calculating it on the fly until they fix it
                aid: str = self.hash.get_aid(flow)

                # we assume all flows with event_type=alert are marked as malicious by suricata
                label =  'malicious' if line['event_type'] == 'alert' else 'benign'
                flow = {
                    'aid' : aid,
                    'label' : label,
                    'timestamp': timestamp,
                    'original_ts': original_ts,
                    }


                # if a flow is not stored in the db, it's because it
                # was found in suricata but not in the gt
                if self.db.store_flow(flow, 'suricata'):
                    if self.is_first_flow:
                        # set the first tw as benign by default
                        self.label_tw(timestamp, line['src_ip'], 'benign')
                        self.is_first_flow = False

                    flows_count += 1
                    # used for printing the stats in the main.py
                    self.db.store_flows_count('suricata', flows_count)

                    if flow['timestamp'] > self.tw_end:
                        # this is a new tw. add the label for it in the db
                        self.label_tw(timestamp, line['src_ip'], 'benign')
                        # update the start and end of this tw
                        self.tw_start = self.tw_end
                        self.tw_end = self.tw_start + self.twid_width

                    if 'malicious' in label.lower():
                        self.label_tw(timestamp, line['src_ip'], 'malicious')

            self.print_stats()



