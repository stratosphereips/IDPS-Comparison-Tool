import sys
import traceback

import utils.timestamp_handler
from typing import (
    Tuple,
    List,
    Optional,
    Union,
    )
from re import findall
from parsers.config import ConfigurationParser
from utils.timewindow_handler import TimewindowHandler
from utils.file_handler import validate_path
from utils.hash import Hash
from abstracts.parsers import Parser
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
    unknown_labels = 0
    benign_labels = 0
    malicious_labels = 0
    # this should be number of first tw - 1 to be able to lael the first tw
    last_registered_tw = 0
    # every time a tw is registered, its' number will be saved here
    registered_tws: List[int] = []
    tool_name = "ground_truth"
    is_first_flow = True

    def init(self, args: list):
        ground_truth = args[0]
        self.gt_zeek_dir = None
        self.gt_zeek_file = None
        if os.path.isdir(ground_truth):
            # zeek dir with ground truth labels
            self.gt_zeek_dir: str = ground_truth
        else:
            self.gt_zeek_file  = ground_truth
        if not validate_path(self.gt_zeek_dir or self.gt_zeek_file):
            raise TypeError(f"Invalid GT path"
                            f" {self.gt_zeek_dir or self.gt_zeek_file}")
        # check the type of the given zeek file/dir with
        # ground truth labels. 'tab-separated' or 'json'?
        self.zeek_file_type: str = self.check_type()
        self.read_config()
        self.timestamp_handler = utils.timestamp_handler.TimestampHandler()


    def read_config(self):
        config = ConfigurationParser()
        self.twid_width = float(config.timewindow_width())
    
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
                self.log(f"skipping flow. can't extract saddr, sport, "
                         f"daddr, dport from line:", line)
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
        zeek sets the type of icmp to the sport field, and the code to the
        dport field, handle that
        :return: same flow with the type and code fields
        """
        if flow['proto'].lower() != 'icmp':
            return flow

        flow['type'] = flow['sport']
        flow['code'] = flow['dport']

        return flow

    def get_flow(self, line) -> Optional[dict]:
        """
        given a tab or json line, extracts the src and dst addr, sport and
        proto from the line
        :param line: is a str if the type of given file is tab separated, or
         a dict if it's json
        :return: dict with {'saddr', 'sport':.. , 'daddr', 'proto'} or
        None when there's a problem extracting flow
        """
        if len(line) < 5:
            # invalid line
            return
        
        if self.zeek_file_type == 'json':
            flow: dict = self.extract_json_fields(line)
        elif self.zeek_file_type == 'tab-separated':
            flow: dict = self.extract_tab_fields(line)
        else:
            return
        
        if not flow:
            return

        flow = self.handle_icmp(flow)
        return flow


    def extract_label_from_line(self, line:str) -> str:
        """
        :param line: a zeek tab separated line
        :return: malicious, benign or unknown
        """
        pattern = r"Malicious[\s\t]+"
        if findall(pattern, line):
            return 'malicious'

        pattern = r"Benign[\s\t]+"
        if findall(pattern, line):
            return 'benign'
        
        return 'unknown'

    def update_labels_ctr(self, label: str):
        """
        update the malicious, benign and unknown labels ctr
        :param label: malicious, benign, unknown
        """
        if label == 'malicious':
            self.malicious_labels += 1
        elif label == 'benign':
            self.benign_labels += 1
        else:
            self.unknown_labels += 1

    def handle_zeek_json(self, line:str) -> Tuple[str,str,str,str]:
        """
        :param line: json line as read from the zeek file
        :return: returns a tuple of label, aid ts and srcip
        """
        try:
            line = json.loads(line)
        except json.decoder.JSONDecodeError:
            self.log(f"Error loading line: \n",'line', error=True)
            return False

        aid = self.handle_getting_aid(line)
        if not aid:
            return False

        label = line.get('label', '')
        self.update_labels_ctr(label)

        return label, aid, line['ts'], line['id.orig_h']

    def handle_getting_aid(self, line: list) -> Optional[str]:
        # first extract fields
        if flow := self.get_flow(line):
            # we managed to extract the fields needed to calc the community id
            return self.hash.get_aid(flow)
        return

    def handle_zeek_tabs(self, line:str) -> Optional[Tuple[str,str,str,str]]:
        """
        :param line: tab separated line as read from the zeek file
        :return: returns a tuple of label, aid ts and srcip or None if
        unable to extract the flow
        """
        label = self.extract_label_from_line(line)
        self.update_labels_ctr(label)

        # the data is either \t separated or space separated
        # zeek files that are space separated are either separated by 2 or 3
        # spaces so we can't use python's split()
        # using regex split, split line when you encounter more than 2 spaces
        # in a row
        line: List[str] = line.split('\t') if (
                '\t' in line) \
            else split(r'\s{2,'r'}', line)

        aid = self.handle_getting_aid(line)
        if not aid:
            return

        return label, aid, line[0], line[2]
        
    def extract_fields(self, line: str) -> Tuple[Union[bool,dict], str]:
        """
        extracts the label and community id from the given line
        uses zeek_file_type to extract fields based on the type of the given
         zeek dir
        completely ignores gt flows that have labels other than benign or
        malicious
        :param line: line as read from the zeek log file
        :return:
        If it managed to extract the flow, returns the
            extracted flow dict and no errors
        If not, returns False and the error
        """
        if self.zeek_file_type == 'json':
            flow = self.handle_zeek_json(line)
        elif self.zeek_file_type == 'tab-separated':
            flow = self.handle_zeek_tabs(line)
        
        if not flow:
            return False, "Invalid flow"
        
        try:
            if flow[0] == "unknown":
                return False, f"Unsupported flow label '{flow[0]}'"

            return {
               'label':  flow[0],
               'aid': flow[1],
               'timestamp': flow[2],
               'srcip': flow[3],
            }, ""
        except (IndexError, TypeError) as e:
            # one of the above 2 methods failed to parse the given line
            return False, f"Problem extracting flow: {line} .. {e}"


    def register_timewindow(self, ts) -> dict:
        """
        registers a new timewindow if the ts doesn't belong to
         an existing one.
        :param ts: unix ts of the flow being parsed
        returns the number of the registered tw and a bool indicating
        whether the tw was registered before or not
        """
        ts = float(ts)

        if self.is_first_flow:
            self.is_first_flow = False
            # first timestamp ever seen in the gt conn.log will be
            # the start of tw1
            self.twid_handler = TimewindowHandler(ts)
            tw_number = 1
        else:
            # let the db decide which tw this is
            # tw number may be negative if a flow is found with a ts < ts
            # of the first flow seen
            tw_number: int = self.db.get_timewindow_of_ts(ts)

        tw_start, tw_end = self.twid_handler.get_start_and_end_ts(
            tw_number
            )
        
        is_labeled_for_the_first_time: bool = self.db.register_tw(
            tw_number,
            tw_start,
            tw_end)
        
        return {
            'tw_number': tw_number,
            'was_registered_before': not is_labeled_for_the_first_time
            }

    def get_full_path(self, filename: str) -> str:
        """
        returns the full path of a given filename
        """
        if not os.path.isabs(filename):
            # this tool is given a zeek dir and we're now parsing 1 logfile
            # from this dir
            # get the full path of the given log file
            return os.path.join(self.gt_zeek_dir, filename)

        # this tool is given a zeek logfile and the path of it is abs
        return filename
    
        
    def was_tw_registered(self, tw: int) -> bool:
        return self.db.is_registered_timewindow(tw)
    
    def should_label_tw(self, tw: int, flow: dict) -> (
            bool):
        """
        determines whether to label the tw or not if:
        1. tw wasnt labeled before for the same IP
        2. twand ip was labeled before as benign and now the label is
        malicious
        
        if the tw was labeled before as malicious and now it's benign,
        we don't update the label.
        
        :param tw: tw number
        :param flow: dict with the srcip and label
        :return: whether or not the current label of this tw should be
        added to the db
        """
        labeled_b4 = self.db.was_tw_labeled_before(
            tw, flow['srcip'], self.tool_name
        )
        
        if not labeled_b4:
            # first label for this tw and this IP
            return True

        if flow['label'] == 'malicious':
            return True
        return False
        

    def label_tw(self, flow: dict, tw_registration_stats: dict):
        """
        labels the timewindow in the db
        :param flow: flow to extract the tw label from
        :param tw_registration_stats: fict with the following keys
             tw: tw number
             was_registered_before: bool indicating with whether the tw was
            registered before in the db or not
        """
        if not self.should_label_tw(
                tw_registration_stats["tw_number"],
                flow
            ):
            return False
        
        self.db.set_gt_label_for_tw(
            flow['srcip'],
            tw_registration_stats["tw_number"],
            flow['label']
        )


    def parse_file(self, filename: str):
        """
        extracts the label and community id from each flow and stores them
         in the db
        Completely ignores flows that dont have benign or malicious in
        their labels, e.g background flows
        :param filename: the name of the zeek logfile without the path,
        for example conn.log
        this can be the file given to this tool using -gtf or 1 file
         from the zeek dir given to this tool
        """
        fullpath = self.get_full_path(filename)
        self.total_flows_read = 0
        gt_file = open(fullpath)
        line_number = 0
        while line := gt_file.readline():
            line_number += 1
            # skip comments
            if line.startswith('#'):
                continue
            
            flow, err = self.extract_fields(line)
            if not flow:
                self.log(f"{err}. Skipping flow at line",
                         line_number,
                         error=True)
                continue
            
            tw_registration_stats: dict = self.register_timewindow(
                flow['timestamp']
                )
            self.label_tw(
                flow,
                tw_registration_stats
                )

            self.total_flows_read += 1

            self.db.store_ground_truth_flow(flow)
            self.db.store_flow(flow, self.tool_name)
            # used for printing the stats in the main.py
            self.db.store_flows_count(self.tool_name, self.total_flows_read)

            if self.total_flows_read % 180 == 0:
                self.log("Parsed ground truth flows so far: ",
                         self.total_flows_read,
                         log_to_results_file=False,
                         end="\r")
        gt_file.close()
        
    def log_stats(self):
        print('\n')
        self.log('', "-" * 30)

        self.log("Total parsed ground truth flows: ", self.total_flows_read)
        self.log("Total aid collisions (discarded flows) found in ground truth: ",
                 self.db.get_aid_collisions())
        self.log("Total flows read: ", self.total_flows_read)
        self.log(f"Total malicious labels: ", self.malicious_labels)
        self.log(f"Total benign labels: ", self.benign_labels )
        self.log(f"Total unknown labels: ", self.unknown_labels)
        self.log('', "-" * 30)

        total_tws = self.db.get_tws_count()
        self.log(f"Total registered timewindows by the ground truth: ",
                 f"{total_tws}. ")
        print()

    def get_line_type(self, log_file_path: str):
        """
        determines whether the given file is json or tab separated by
        reading the first line of it
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
        if self.gt_zeek_dir:
            # open the first logfile you see in this dir
            for f in os.listdir(self.gt_zeek_dir):
                if self.is_ignored(f):
                    continue

                full_path = os.path.join(self.gt_zeek_dir, f)
                if os.path.isfile(full_path):
                    type_ = self.get_line_type(full_path)
                    break
        elif self.gt_zeek_file:
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
        :return: 0 if all good, 1 if an error occured
        """
        try:
            if self.gt_zeek_dir:
                for log_file in os.listdir(self.gt_zeek_dir):
                    if self.is_ignored(log_file):
                        continue
                    # extract fields and store them in the db
                    self.parse_file(log_file)
    
            elif self.gt_zeek_file:
                # extract fields and store them in the db
                self.parse_file(self.gt_zeek_file)
    
            self.log_stats()
            os._exit(0)
        except Exception as e:
            self.log("An error occurred: ", e, error=True)
            self.log("",f"{traceback.format_exc()}",
                     error=True)
            os._exit(1)


