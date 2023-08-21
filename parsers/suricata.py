from database.sqlite_db import SQLiteDB
from termcolor import colored
import json

from .utils import get_community_id

class SuricataParser:
    name = "SuricataParser"
    def __init__(self, eve_file: str, db: SQLiteDB):
        self.eve_file: str = eve_file
        self.db = db

    def log(self, green_txt, normal_txt):
        normal_txt = str(normal_txt)
        green_txt = str(green_txt)

        print(colored(f'[{self.name}] ', 'blue') + colored(green_txt,'green') + normal_txt)

    def parse(self):
        """read sthe given suricata eve.json"""
        with open(self.eve_file, 'r') as f:
            flows = 0
            while line := f.readline():
                line = json.loads(line)
                flows += 1

                if line['event_type'] == 'stats':
                    continue

                #TODO suricata calculates the cid in a wrong way, we'll be calculating it on the fly until they fix it
                cid: str = get_community_id({
                'saddr': line['src_ip'],
                'daddr': line['dest_ip'],
                'sport': line['src_port'],
                'dport': line['dest_port'],
                'proto': line['proto'].lower(),
                })

                if line['event_type'] == 'alert':
                    flow = {
                        'community_id' : cid,
                        # todo we assume all flows with event_type=alert are marked as malicious by suricata
                        'label' : 'malicious'
                    }
                else:
                    flow = {
                        'community_id' : cid,
                        'label' : 'benign'
                    }

                self.db.store_flow(flow, 'suricata_label')
                self.log(f"Extracted suricata label for flow: ",  cid )
            self.db.store_flows_count('suricata', flows)


