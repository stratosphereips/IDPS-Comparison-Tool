from database.sqlite_db import SQLiteDB
from termcolor import colored
from parsers.config import ConfigurationParser
from utils.hash import Hash
from abstracts.abstracts import Parser
from re import split
import json
import os

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

class GroundTruthParser(Parser):
    name = "GroundTruthParser"
    hash = Hash()
    def init(self,
             ground_truth=None,
             ground_truth_type=None):
        # ground_truth_type can either be 'dir' or 'file'
        if ground_truth_type == 'dir':
            # zeek dir with ground truth labels
            self.gt_zeek_dir: str = ground_truth
        elif ground_truth_type == 'file':
            self.gt_zeek_file  = ground_truth

        # check th etype of the given zeek file/dir with ground truth labels. 'tab-separated' or 'json'?
        self.zeek_file_type: str = self.check_type()
        self.read_config()

    def read_config(self):
        config = ConfigurationParser('config.yaml')
        self.twid_width = config.timewindow_width()

    def extract_tab_fields(self, line):
        try:
            return {
                'timestamp': line[0],
                'saddr': line[2],
                'sport':  line[3],
                'daddr':  line[4],
                'dport':  line[5],
                'proto':  line[6],
            }
        except KeyError:
            return False


    def extract_json_fields(self, line):
        ts = line.get('ts')
        saddr = line.get('id.orig_h')
        daddr = line.get('id.resp_h')
        sport = line.get('id.orig_p')
        dport = line.get('id.resp_p')
        proto = line.get('proto')

        for field in (saddr, daddr, sport, dport, proto, ts):
            if field == None:
                self.log(f"skipping flow. can't extract saddr, sport, daddr, dport from line:", line)
                # todo handle this
                return False

        return {
            'timestamp': ts,
            'saddr':saddr,
            'daddr': daddr,
            'sport': sport,
            'dport': dport,
            'proto': proto
        }


    def handle_icmp(self, flow: dict) -> dict:
        """
        zeek sets the type of icmp to the sport field, and the code to the dport field, handle that
        :return: same flow with the type and code fields
        """
        if flow['proto'].lower() != 'icmp':
            return flow

        flow['type'] = flow['sport']
        flow['code'] = flow['dport']

        return flow

    def get_flow(self, line):
        """
        given a tab or json line, extracts the src and dst addr, sport and proto from the line
        :param line: is a str if the type of given file is tab separated, or a dict if it's json
        :return: dict with {'saddr', 'sport':.. , 'daddr', 'proto'}
        """
        if self.zeek_file_type == 'json':
            flow: dict = self.extract_json_fields(line)
        elif self.zeek_file_type == 'tab-separated':
            flow: dict = self.extract_tab_fields(line)

        if not flow:
            return False

        flow = self.handle_icmp(flow)

        return flow


    def extract_label_from_line(self, line:str) -> str:
        if 'benign' in line or 'Benign' in line:
            return 'benign'
        elif 'malicious' in line or 'Malicious' in line:
            return 'malicious'
        else:
            # line doesn't have a label
            # print(f"line: {line} doesn't have a label!")
            return 'benign'

    def handle_zeek_json(self, line:str):
        try:
            line = json.loads(line)
        except json.decoder.JSONDecodeError:
            self.log(f"Error loading line: \n{line}",'')
            return False

        aid = self.handle_getting_aid(line)
        if not aid:
            return False

        label =  line.get('label', 'benign')
        return label, aid, line['ts']

    def handle_getting_aid(self, line: list):
        # first extract fields
        if flow := self.get_flow(line):
            # we managed to extract the fields needed to calc the community id
            return self.hash.get_aid(flow)
        return False

    def handle_zeek_tabs(self, line:str):
        label = self.extract_label_from_line(line)

        # the data is either \t separated or space separated
        # zeek files that are space separated are either separated by 2 or 3
        # spaces so we can't use python's split()
        # using regex split, split line when you encounter more than 2 spaces in a row
        line = line.split('\t') if '\t' in line else split(r'\s{2,}', line)

        aid = self.handle_getting_aid(line)
        if not aid:
            return False

        return label, aid, line[0]

    def extract_fields(self, line: str) -> dict:
        """
        extracts the label and community id from the given line
        uses zeek_file_type to extract fields based on the type of the given zeek dir
        :param line: line as read from the zeek log file
        :return: returns a flow dict with {'aid': ..., 'label':...}
        """
        if self.zeek_file_type == 'json':
            flow = self.handle_zeek_json(line)
        elif self.zeek_file_type == 'tab-separated':
            flow = self.handle_zeek_tabs(line)

        try:
            return {
               'label':  flow[0],
               'aid': flow[1],
               'timestamp': flow[2],
            }
        except TypeError:
            # unable to handle the line
            return False


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

        flows_count = 0
        with open(fullpath, 'r') as f:
            while line := f.readline():
                # skip comments
                if line.startswith('#'):
                    continue
                flow = self.extract_fields(line)
                if not flow:
                    continue
                flows_count += 1
                self.db.store_ground_truth_flow_ts(flow)
                self.db.store_flow(flow, 'ground_truth')
                # used for printing the stats in the main.py
                self.db.store_flows_count('ground_truth', flows_count)
                if flows_count % 180 == 0:
                    self.log("Parsed ground truth flows: ", flows_count)


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




