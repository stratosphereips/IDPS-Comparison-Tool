import os
import sys
from threading import Thread
from typing import Tuple, List
from typing import Optional
from parsers.config import ConfigurationParser
from parsers.suricata import SuricataParser
from parsers.cm_db import ConfusionMatrixDBParser
from database.sqlite_db import SQLiteDB
from parsers.arg_parser import ArgsParser
from parsers.slips import SlipsParser
from parsers.ground_truth import GroundTruthParser
from comparisons.flow_by_flow import FlowByFlow
from comparisons.per_timewindow import PerTimewindow
from metrics.calculator import Calculator
from contextlib import suppress
from shutil import rmtree
from termcolor import colored
import datetime
import multiprocessing
from time import time, sleep
from abstracts.observer import IObservable
from logger.logger import Logger
class Main(IObservable):
    name = 'Main'
    starttime = time()
    args = ArgsParser().args
    stop_stats_thread = False

    def __init__(self):
        # call the IObservable() init
        super(Main, self).__init__()
        self.output_dir = self.setup_output_dir()
        self.results_path = os.path.join(self.output_dir, 'results.txt')
        # init the logger
        self.logger = Logger(self.name, self.results_path)
        self.add_observer(self.logger)

        self.db = SQLiteDB(self.output_dir)
        self.add_metadata()
        self.log(f"Storing results in: ", self.results_path)


    def setup_output_dir(self):
        output_dir = 'output/'
        current_datetime = datetime.datetime.now()
        output_dir = os.path.join(output_dir, current_datetime.strftime('%Y-%m-%d-%H:%M:%S') + '/')

        # todo add support for -o
        # delete all old files in the output dir
        if os.path.exists(output_dir):
            # this will be used when -o is supported
            self.log(f"Overwriting all files in {output_dir}",'')
            for file in os.listdir(output_dir):
                file_path = os.path.join(output_dir, file)
                with suppress(Exception):
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                    elif os.path.isdir(file_path):
                        rmtree(file_path)
        else:
            os.makedirs(output_dir)
        self.log(f"Storing output in: ", output_dir)
        return output_dir


    def log(self, green_txt, normal_txt):
        self.notify_observers((normal_txt, green_txt))


    def start_slips_parser(self):
        # this has to be the path of the sqlite3 db generated by slips with all the labels and community IDs
        slips_db: str = self.args.slips_db
        if self.validate_path(slips_db):
            self.log(f"Reading Slips db from: ", slips_db)
        assert os.path.isfile(slips_db), f"Slips DB should be a file, not a dir"
        SlipsParser(self.output_dir, self.results_path, slips_db=slips_db).parse()

    def start_suricata_parser(self):
        eve_file: str = self.args.eve_file
        if self.validate_path(eve_file):
            self.log(f"Using suricata: ", eve_file)
        assert os.path.isfile(eve_file), f"Suricata eve.json should be a file, not a dir"
        # read suricata eve.json
        SuricataParser(self.output_dir, self.results_path, eve_file=eve_file).parse()

    def start_ground_truth_parser(self):
        if self.args.ground_truth_dir:
            # read the ground truth and store it in the db
            GroundTruthParser(
                self.output_dir,
                self.results_path,
                ground_truth=self.args.ground_truth_dir,
                ground_truth_type='dir',
                ).parse()

        elif self.args.ground_truth_file:
            # read the ground truth and store it in the db
            GroundTruthParser(
                self.output_dir,
                self.results_path,
                ground_truth=self.args.ground_truth_file,
                ground_truth_type='file',
                ).parse()


    def validate_path(self, path):
        """make sure this path is abs and exists"""
        if not os.path.isabs(path):
            self.log(f"Invalid os.path. {path} must be absolute. Stopping.", '')
            sys.exit()
        assert os.path.exists(path), f"Path '{path}' doesn't exist"
        return True

    def start_parsers(self, print_stats_event):
        """
        runs each parser in a separate proc and returns when they're all done
        :param print_stats_event: the thread will set this event when it's done reading the ground truth flows and
        started reading slips and suricata flows so the print_stats thread can start printing
        """
        gt_parser: multiprocessing.Process = multiprocessing.Process(target=self.start_ground_truth_parser, args=( ))
        suricata_parser: multiprocessing.Process = multiprocessing.Process(target=self.start_suricata_parser, args=( ))
        slips_parser: multiprocessing.Process = multiprocessing.Process(target=self.start_slips_parser, args=( ))

        gt_parser.start()
        self.log(f"New process started for parsing: ", 'Ground Truth')
        gt_parser.join()

        # since we discard slips and suricata's flows based on the ground truth flows,
        # we need to make sure we're done  reading them first
        suricata_parser.start()
        self.log(f"New process started for parsing: ", 'Suricata')

        slips_parser.start()
        self.log(f"New process started for parsing: ", 'Slips')

        print_stats_event.set()

        suricata_parser.join()
        slips_parser.join()
        self.log('', "-" * 30)


    def print_stats(self, print_stats_event):
        """
        thread that prints the total parsed flows by all parsers every once in a while
        :param db:
        :return:
        """
        print_stats_event.wait()

        while not self.stop_stats_thread:
            sleep(5)
            current_datetime = datetime.datetime.now()
            now = current_datetime.strftime('%Y-%m-%d %H:%M:%S')
            print(f"{now} - Total parsed flows by "
                  f"slips: {self.db.get_flows_parsed('slips')} "
                  f"suricata: {self.db.get_flows_parsed('suricata')} ", end='\r')


    def add_metadata(self):
        """
        Adds tool versions and files used
        to metadata.txt in the outupt dir
        """
        metadata_file = os.path.join(self.output_dir, 'metadata.txt')
        self.log("Storing metadata in: ", metadata_file)

        # Read the configuration file
        config = ConfigurationParser('config.yaml')
        slips_version = config.slips_version()
        suricata_version = config.suricata_version()

        with open(metadata_file, 'w') as metadata:
            metadata.write(f"Slips version: {slips_version} \n"
                           f"Suricata version: {suricata_version}\n\n"
                           f"Ground truth: "
                           f"{self.args.ground_truth_dir or self.args.ground_truth_file}\n"
                           f"Slips DB: {self.args.slips_db}\n"
                           f"Suricata file: {self.args.eve_file}\n")

    def print_flows_parsed_vs_discarded(self, tool: str):
        """
        print the flows parsed, discarded and
        actual flows taken into consideration in the calculations by the given
        tool
        :param tool: slips or suricata
        """
        parsed_flows: int = self.db.get_flows_parsed(tool)
        discarded_flows: int = self.db.get_discarded_flows(tool)
        used_flows: int =  parsed_flows - discarded_flows
        if not discarded_flows:
            used_flows = parsed_flows

        self.log(f"Total read flows by {tool} (doesn't include discarded flows): {parsed_flows}  -- "
                 f"Discarded flows: {discarded_flows}", '')

    def validate_gt(self):
        # this should always be a labeled zeek json dir
        if self.args.ground_truth_dir:
            ground_truth_dir: str = self.args.ground_truth_dir
            if self.validate_path(ground_truth_dir):
                self.log(f"Using ground truth dir: ", ground_truth_dir)
            assert os.path.isdir(ground_truth_dir), f"Invalid dir {ground_truth_dir}. ground truth has to be a dir"

        elif self.args.ground_truth_file:
            ground_truth_file: str = self.args.ground_truth_file
            if self.validate_path(ground_truth_file):
                self.log(f"Using ground truth file: ", ground_truth_file)
            assert os.path.isfile(self.args.ground_truth_file), f"Invalid file given with -gtf {self.args.ground_truth_file}. "
        else:
            print("No ground truth file or dir was given. stopping.")
            sys.exit()


    def read_cm_db(self):
        """
        starts the confusion matrix db parser
        """
        self.log("Consusion matrix database parser started using:",
                 self.args.confusion_matrix_db)
        cm: dict = ConfusionMatrixDBParser(
            self.output_dir,
            db_full_path=self.args.confusion_matrix_db).parse()

        for tool in ('slips', 'suricata'):
            # dont pass the calc lists with actual and predicted data as the cm is already calculated
            calc = Calculator(tool, [],[], self.output_dir)
            calc.metrics = cm
            for metric in (
                calc.FPR,
                calc.FNR,
                calc.TPR,
                calc.TNR,
                calc.recall,
                calc.precision,
                calc.F1,
                calc.accuracy,
                calc.MCC,
            ):
                metric()
            self.log(' ', ' ')

    def calc_metrics(self,
            comparer,
            tool: str,
    ):
        """
        runs all calculator methods using the given method (comparer obj) on the given tool
        :param comparer: obj of FlowByFlow class or PerTimewindow class
        :param tool: slips or suricata
        """


    def main(self):

        if self.args.confusion_matrix_db:
            """
            given a db with pre-calculated TP, TN FP, FN for each tool
            continue analysis from here
            """
            self.read_cm_db()

        else:
            self.validate_gt()
            # used to tell the print_stats thread to start
            print_stats_event = multiprocessing.Event()

            stats_thread = Thread(target=self.print_stats, args=(print_stats_event,), daemon=True)
            stats_thread.start()

            self.start_parsers(print_stats_event)
            # now that the parses ended don't print more stats
            self.stop_stats_thread = True
            stats_thread.join()


            self.log(' ', ' ')
            self.log('', "-" * 30)
            self.log(f"Total flows read by parsers (doesn't include discarded flows): ",'')
            self.db.print_table('flows_count')

            supported_tools = ('slips', 'suricata')

            self.log(' ', ' ')
            self.log("Flows are discarded when they're found in a tool but not in the ground truth", '')
            for tool in supported_tools:
                self.print_flows_parsed_vs_discarded(tool)


            # before calculating anything, fill out the missing labels with benign
            self.db.fill_null_labels()

            self.log(f"Done. For labels db check: ", self.output_dir)

            self.log(' ', ' ')

            for comparison_method in (FlowByFlow, PerTimewindow):
                # create an obj of the helper class sresponsible for handling this type of comparison
                comparer = comparison_method(self.output_dir)

                self.log('', "-" * 30)
                self.log("Comparison method: ", comparer.name)
                self.log(' ', ' ')

                # now apply this method to all supported tools
                for tool in supported_tools:
                    # get the actual and predicted labels by the tool
                    actual, predicted = comparer.get_labels_lists(tool)
                    calc = Calculator(tool, actual, predicted, self.output_dir)

                    for metric in (
                        calc.get_confusion_matrix,
                        calc.FPR,
                        calc.FNR,
                        calc.TPR,
                        calc.TNR,
                        calc.recall,
                        calc.precision,
                        calc.F1,
                        calc.accuracy,
                        calc.MCC,

                    ):
                        metric()
                    self.log(' ', ' ')


        self.db.close()

        analysis_time = time() - self.starttime
        self.log(f"Analysis time: ",f"{analysis_time/60} mins")



if __name__ == "__main__":
    Main().main()
