import os
import json
from database.sqlite_db import SQLiteDB
from termcolor import colored
from re import split
from .utils import get_community_id

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
        self.zeek_file_type: str = self.check_type()

    def log(self, green_txt, normal_txt):
        normal_txt = str(normal_txt)
        green_txt = str(green_txt)

        print(colored(f'[{self.name}] ', 'blue') + colored(green_txt,'green') + normal_txt)

    def get_flow(self, line):
        """
        given a tab or json line, extracts the src and dst addr, sport and proto from the line
        :param line: is a str if the type of given file is tab separated, or a dict if it's json
        :return: dict with {'saddr', 'sport':.. , 'daddr', 'proto'}
        """
        if self.zeek_file_type == 'json':
            saddr = line.get('id.orig_h')
            daddr = line.get('id.resp_h')
            sport = line.get('id.orig_p')
            dport = line.get('id.resp_p')
            proto = line.get('proto')

            for field in (saddr, daddr, sport, dport, proto):
                if field == None:
                    self.log(f"skipping flow. can't extract saddr, sport, daddr, dport from line:", line)
                    # todo handle this
                    return False
            return {
                'saddr':saddr,
                'daddr': daddr,
                'sport': sport,
                'dport': dport,
                'proto': proto
            }
        elif self.zeek_file_type == 'tab-separated':
            try:
                return {
                    'saddr': line[2],
                    'daddr':  line[4],
                    'sport':  line[3],
                    'dport':  line[5],
                    'proto':  line[6],
                }
            except KeyError:
                return False
    
    def extract_fields(self, line: str) -> dict:
        """
        extracts the label and community id from the given line
        uses zeek_file_type to extract fields based on the type of the given zeek dir
        :param line: line as read from the zeek log file
        :return: returns a flow dict with {'community_id': ..., 'label':...}
        """
        if self.zeek_file_type == 'json':
            try:
                line = json.loads(line)
                community_id: str = line.get('community_id' ,'')
                if not community_id:
                    # the line doesn't have the community id calculated
                    # we will calc it manually
                    # first extract fields
                    flow: dict = self.get_flow(line)
                    if flow:
                        # we managed to extract the fields needed to calc the community id
                        community_id: str = get_community_id(flow)
                    else:
                        return False

            except json.decoder.JSONDecodeError:
                self.log(f"Error loading line: \n{line}",'')
                return False

            # extract fields
            fields = {
               'community_id': community_id,
               'label':  line.get('label', 'benign')
               }

        elif self.zeek_file_type == 'tab-separated':
            # the data is either \t separated or space separated
            # zeek files that are space separated are either separated by 2 or 3 spaces so we can't use python's split()
            # using regex split, split line when you encounter more than 2 spaces in a row
            line = line.split('\t') if '\t' in line else split(r'\s{2,}', line)

            if 'benign' in line or 'Benign' in line:
                label = 'benign'
            elif 'malicious' in line or 'Malicious' in line:
                label = 'malicious'
            else:
                # line doesn't have a label
                # print(f"line: {line} doesn't have a label!")
                label = 'benign'

            # extract the community id
            for field in line:
                if field.startswith("1:"):
                    community_id = field
                    break
            else:
                # the line doesn't have the community id calculated
                # we will calc it manually
                # first extract fields that we need to calc community id
                flow: dict = self.get_flow(line)
                if flow:
                    # we managed to extract the fields needed to calc the community id
                    community_id: str = get_community_id(flow)
                else:
                    return False

            fields = {
               'community_id': community_id,
               'label':  label
            }

        return fields


    def parse_file(self, filename: str):
        """
        extracts the label and community id from each flow and stores them in the db
        :param filename: the name of the logfile without the path, for example conn.log
        this can be the file given to this tool using -gtf or 1 file from the zeek dir given to this tool
        """
        if not os.path.isabs(filename):
            # this tool is given a zeek dir and we're now parsing 1 logfile from this dir
            # get the full path of the given log file
            fullpath = os.path.join(self.gt_zeek_dir, filename)
        else:
            # this tool is given a zeek logfile and the path of it is abs
            fullpath = filename

        self.log(f"Extracting ground truth labels from: ", f"{fullpath}")

        with open(fullpath, 'r') as f:
            while line := f.readline():
                # skip comments
                if line.startswith('#'):
                    continue
                self.flows_count +=1
                if self.flows_count % 180 == 0:
                    self.log(f"Number of parsed flows: ", self.flows_count)
                flow = self.extract_fields(line)
                if not flow:
                    # skip the flow that doesn't have a community
                    # id after trying to extract it and manually calc it
                    continue
                self.db.store_flow(flow, 'ground_truth')

    def get_line_type(self, log_file_path: str):
        """
        determines whether the given file is json or tab separated by reading the first line of it
        :param log_file_path: path of file we wanna determine the type of
        :return: 'tab-separated' or 'json'
        """
        with open(log_file_path, 'r') as log_file:
            # read the first line and determine if it's tab separated or not
            first_line = log_file.readline()
            if 'separator' in first_line:
                type_ = 'tab-separated'
            else:
                try:
                    json.loads(first_line)
                    type_ = 'json'
                except json.decoder.JSONDecodeError:
                    type_ = 'tab-separated'
        return type_

    def check_type(self) -> str:
        """
        checks if the given dir is json or tab seperated zeek dir
        :Return: 'tab-separated' or 'json'
        """
        if hasattr(self, 'gt_zeek_dir'):
            # open the first logfile you see in this dir
            for f in os.listdir(self.gt_zeek_dir):
                if self.is_ignored(f):
                    continue

                full_path = os.path.join(self.gt_zeek_dir, f)
                if os.path.isfile(full_path):
                    type_ = self.get_line_type(full_path)
                    break
        elif hasattr(self, 'gt_zeek_file'):
            type_ = self.get_line_type(self.gt_zeek_file)

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


