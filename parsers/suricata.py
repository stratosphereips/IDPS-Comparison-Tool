from database.sqlite_db import SQLiteDB
from termcolor import colored
import json

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
            while line := f.readline():
                line = json.loads(line)
                if line['event_type'] == 'alert':
                    #TODO see what's the key for community id
                    flow = {
                        'community_id' : line.get("community_id" ,''),
                        # todo we assume all flows with event_type=alert are marked as malicious by suricata
                        'label' : 'malicious'
                    }
                    self.db.store_flow(flow, 'suricata_label')
                else:
                    #TODO see what's the key for community id
                    flow = {
                        'community_id' : line.get("community_id" ,''),
                        # todo we assume all flows with event_type=alert are marked as malicious by suricata
                        'label' : 'benign'
                    }
                    self.db.store_flow(flow, 'suricata_label')

                self.log(f"Extracted suricata label for flow: ",  line.get("community_id" ,''))



