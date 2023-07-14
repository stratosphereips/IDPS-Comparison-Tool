import os
import json
from database.sqlite_db import SQLiteDB
from termcolor import colored
from re import split

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

    def __init__(self, ground_truth: str, ground_truth_type:str, db: SQLiteDB):
        self.db = db
        # ground_truth_type can either be 'dir' or 'file'
        if ground_truth_type == 'dir':
            # zeek dir with ground truth labels
            self.gt_zeek_dir: str = ground_truth
        elif ground_truth_type == 'file':
            self.gt_zeek_file  = ground_truth

        # check th etype of the given zeek file/dir with ground truth labels. 'tab-separated' or 'json'?
        self.zeek_dir_type: str = self.check_type()

    def log(self, green_txt, normal_txt):
        normal_txt = str(normal_txt)
        green_txt = str(green_txt)

        print(colored(f'[{self.name}] ', 'blue') + colored(green_txt,'green') + normal_txt)

    def extract_fields(self, line: str) -> dict:
        """
        extracts the label and community id from the given line
        uses zeek_dir_type to extract fields based on the type of the given zeek dir
        :param line: line as read from the zeek log file
        :return: returns a flow dict with {'community_id': ..., 'label':...}
        """
        if self.zeek_dir_type == 'json':
            try:
                line = json.loads(line)
            except json.decoder.JSONDecodeError:
                self.log(f"Error loading line: \n{line}",'')

            # extract fields
            fields = {
               'community_id': line.get('community_id', ''),
               'label':  line.get('label', '')
               }
        elif self.zeek_dir_type == 'tab-separated':
            # the data is either \t separated or space separated
            # zeek files that are space separated are either separated by 2 or 3 spaces so we can't use python's split()
            # using regex split, split line when you encounter more than 2 spaces in a row
            line = line.split('\t') if '\t' in line else split(r'\s{2,}', line)

            if 'benign' in line or 'Benign' in line:
                label = 'benign'
            elif 'malicious' in line or 'Malicious' in line:
                label = 'malicious'

            # extract the community id
            community_id = ''
            for field in line:
                if field.startswith("1:"):
                    community_id = field
                    break

            fields = {
               'community_id': community_id,
               'label':  label
            }

        return fields


    def parse_file(self, filename: str):
        """
        extracts the label and community id from each flow and stores them in the db
        :param filename: the name of the logfile without the path, for example conn.log
        """
        # get the full path of the given log file
        fullpath = os.path.join(self.zeek_dir, filename)
        self.log(f"Extracting ground truth labels from: ", f"{fullpath}")

        with open(fullpath, 'r') as f:
            while line := f.readline():

                # skip comments
                if line.startswith('#'):
                    continue

                self.flows_count +=1
                #TODO call this in tab conn.log
                flow = self.extract_fields(line)
                self.db.store_flow(flow, 'ground_truth')

    def check_type(self) -> str:
        """
        checks if the given dir is json or tab seperated zeek dir
        :Return: 'tab-separated' or 'json'
        """
        for f in os.listdir(self.zeek_dir):
            full_path = os.path.join(self.zeek_dir,f)
            # open the first logfile you see in this dir
            if os.path.isfile(full_path):
                with open(full_path, 'r') as random_logfile:
                    first_line = random_logfile.readline()
                    if 'separator' in first_line:
                        dir_type = 'tab-separated'
                    else:
                        try:
                            json.loads(first_line)
                            dir_type = 'json'
                        except json.decoder.JSONDecodeError:
                            dir_type = 'tab-separated'
                break
        return dir_type

        return type_

    def is_ignored(self, log_file:str):
        """
        checks if the given log file path is ignored or not
        :return:
        """
        base_filename, ext = os.path.splitext(log_file)
        if base_filename in IGNORED_LOGS:
            return True

    def parse(self):
        """
        parses the given zeek dir or zeek logfile
        """
        if hasattr(self, 'gt_zeek_dir'):
            for log_file in os.listdir(self.gt_zeek_dir):
                if self.is_ignored(log_file):
                    continue

                # extract fields and store them in the db
                self.parse_file(log_file)

        elif hasattr(self, 'gt_zeek_file'):
            # extract fields and store them in the db
            self.parse_file(self.gt_zeek_file)

        self.db.store_flows_count('ground_truth', self.flows_count)


