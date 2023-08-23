from database.sqlite_db import SQLiteDB
from termcolor import colored
import json

from .utils import get_community_id, convert_iso_8601_to_unix_timestamp

class SuricataParser:
    name = "SuricataParser"
    def __init__(self, eve_file: str, db: SQLiteDB):
        self.eve_file: str = eve_file
        self.db = db

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

                # todo handle icmp
                # {'timestamp': '1970-01-01T02:00:00.000016+0200', 'flow_id': 806511107004851, 'event_type': 'flow', 'src_ip': 'fe80:0000:0000:0000:d5e6:502a:54ce:e387', 'dest_ip': 'ff02:0000:0000:0000:0000:0000:0000:0002', 'proto': 'IPv6-ICMP', 'icmp_type': 133, 'icmp_code': 0, 'flow': {'pkts_toserver': 3, 'pkts_toclient': 0, 'bytes_toserver': 210, 'bytes_toclient': 0, 'start': '1970-01-01T02:00:10.678323+0200', 'end': '1970-01-01T02:00:18.679102+0200', 'age': 8, 'state': 'new', 'reason': 'shutdown', 'alerted': False}, 'community_id': '1:kRuEWzfQpgjU3t+9Uf3kvfhRuA0='}

                #{"timestamp":"1970-01-01T02:00:00.000016+0200","flow_id":81604379302370,"event_type":"flow","src_ip":"fe80:0000:0000:0000:d5e6:502a:54ce:e387","dest_ip":"ff02:0000:0000:0000:0000:0000:0000:0016","proto":"IPv6-ICMP","icmp_type":143,"icmp_code":0,"flow":{"pkts_toserver":2,"pkts_toclient":0,"bytes_toserver":180,"bytes_toclient":0,"start":"1970-01-01T02:00:10.678370+0200","end":"1970-01-01T02:00:11.178825+0200","age":1,"state":"new","reason":"shutdown","alerted":false},"community_id":"1:1wlgkbwn0/hDVbFA0hD7tRnEH9w="}


                if event_type == 'stats':
                    continue

                flow: dict = self.extract_flow(line)
                timestamp = convert_iso_8601_to_unix_timestamp(flow['timestamp'])

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


