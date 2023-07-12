import os
import json
from database.sqlite_db import SQLiteDB
from termcolor import colored
# these are the files that slips doesn't read
IGNORED_LOGS = {
    'capture_loss',
    'loaded_scripts',
    'packet_filter',
    'stats',
    'ocsp',
    'reporter',
    'x509',
    'pe',
    'mqtt_publish',
    'mqtt_subscribe',
    'mqtt_connect',
    'analyzer',
    'ntp',
    'radiuss',
    'sip',
    'syslog'
}

class GroundTruthParser:
    name = "GroundTruthParser"
    flows_count = 0

    def __init__(self, zeek_dir: str, db: SQLiteDB):
        self.zeek_dir: str = zeek_dir
        self.db = db

    def log(self, green_txt, normal_txt):
        normal_txt = str(normal_txt)
        green_txt = str(green_txt)

        print(colored(f'[{self.name}] ', 'blue') + colored(green_txt,'green') + normal_txt)


    def extract_fields(self, filename: str):
        """
        extracts the label and community id from each flow and stores them in the db
        :param filename: the name of the logfile without the path, for example conn.log
        """
        # get the full path of the given log file
        fullpath = os.path.join(self.zeek_dir, filename)
        self.log(f"Extracting ground truth labels from: ", f"{fullpath}")
        with open(fullpath, 'r') as f:
            while line := f.readline():
                self.flows_count +=1
                try:
                    line = json.loads(line)
                except json.decoder.JSONDecodeError:
                    self.log(f"Error loading line: \n{line}",'')

                # extract fields
                fields = {
                   'community_id': line.get('community_id', ''),
                   'label':  line.get('label', '')
                   }
                self.db.store_flow(fields, 'ground_truth')


    def parse(self):
        """
        parses each log file in self.zeek_dir
        :return:
        """
        for file in os.listdir(self.zeek_dir):
            # skip ignored logs
            base_filename, ext = os.path.splitext(file)
            if base_filename in IGNORED_LOGS:
                continue

            # extract fields and store them in the db
            self.extract_fields(file)

        self.db.store_flows_count('ground_truth', self.flows_count)




