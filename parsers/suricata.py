from utils.timewindow_handler import TimewindowHandler
from utils.timestamp_handler import TimestampHandler
from utils.hash import Hash
from abstracts.parsers import Parser
from database.sqlite_db import SQLiteDB

import json


class SuricataParser(Parser):
    name = "SuricataParser"
    malicious_labels = 0
    benign_labels = 0

    def init(self,
             eve_file=None):
        self.eve_file: str = eve_file
        # to be able to get the ts of the first flow
        self.is_first_flow = True
        self.hash = Hash()
        self.timestamp_handler = TimestampHandler()
        self.discarded_tw_labels = 0

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

    def label_malicious_tw(self, ts, srcip):
        """
        sets the label of the twid where the given ts exists as malicious by suricata
        :param ts: current flow timestamp
        :param srcip: src ip marked as malicious
        :return:
        """
        # if 1 flow is malicious, mark the whole tw as malicious by suricata
        # map this suricata flow to one of the existing(gt) timewindows
        if tw := self.db.get_timewindow_of_ts(ts):
            self.db.set_tw_label(srcip, 'suricata', tw, 'malicious')
            return True

    def warn_about_discarded_alert(self, ts):
        """
        prints a warning when the tool is discarding an alert detected by suricata
        :param ts: ts of the alert found
        """
        self.discarded_tw_labels += 1
        gt_start_time, gt_end_time = self.db.get_timewindows_limit()

        gt_start_time = self.timestamp_handler.convert_to_human_readable(gt_start_time)
        gt_end_time = self.timestamp_handler.convert_to_human_readable(gt_end_time)
        ts = self.timestamp_handler.convert_to_human_readable(ts)

        self.log(f"Problem marking malicious tw: "
                 f"Suricata marked a flow at {ts} as malicious, "
                 f"this flow doesn't belong to any registered timewindow by the ground truth. "
                 f"timewindows in gt start at: {gt_start_time} and end at: {gt_end_time}. ",
                 "discarding alert.")

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

                flows_count += 1

                flow: dict = self.extract_flow(line)

                timestamp = self.timestamp_handler.convert_iso_8601_to_unix_timestamp(flow['timestamp'])
                flow['timestamp'] = timestamp

                #TODO suricata calculates the aid in a wrong way, we'll be calculating it on the fly until they fix it
                aid: str = self.hash.get_aid(flow)
                # todo we assume all flows with event_type=alert are marked as malicious by suricata
                label =  'malicious' if line['event_type'] == 'alert' else 'benign'
                flow = {
                    'aid' : aid,
                    'label' : label,
                    'timestamp': timestamp
                    }


                if 'malicious' in label.lower():
                    self.malicious_labels += 1
                    if not self.label_malicious_tw(timestamp, line['src_ip']):
                        self.warn_about_discarded_alert(timestamp)
                else:
                    self.benign_labels += 1

                self.db.store_flow(
                    flow,
                    'suricata'
                )
                self.db.store_suricata_flow(flow)

                # used for printing the stats in the main.py
                self.db.store_flows_count('suricata', flows_count)

            self.log('', "-" * 30)

            self.log(f"Total malicious labels: ", self.malicious_labels)
            self.log(f"Total benign labels: ", self.benign_labels )
            self.log(f"Total Suricata discarded timewindow labels (due to inability to map the ts to an existing current tw): ",
                     self.discarded_tw_labels )
            self.log('', "-" * 30)

            print()




