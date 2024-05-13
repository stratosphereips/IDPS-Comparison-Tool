import os
import sys
from threading import Thread
from contextlib import suppress
from shutil import rmtree
import datetime
import multiprocessing
from time import time, sleep

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
from abstracts.observer import IObservable
from logger.logger import Logger

class Main(IObservable):
    name = 'Main'
    starttime = time()
    args = ArgsParser().args
    stop_stats_thread = False
    supported_tools = ('slips', 'suricata')

    def __init__(self):
        # call the IObservable() init
        super(Main, self).__init__()
        self.output_dir = self.setup_output_dir()
        self.results_path = os.path.join(self.output_dir, 'results.txt')
        # init the logger
        self.logger = Logger(self.name, self.output_dir)
        self.add_observer(self.logger)
        
        self.read_configuration()

        self.db = SQLiteDB(self.output_dir)
        self.add_metadata()
        self.log(f"Storing results in: ", self.results_path)

    def prep_given_output_dir(self):
        """
        handles the -o arg
        by clearing the given output dir if it's there,
        or creating it if it's not.
        """
        if not os.path.exists(self.args.output_dir):
            os.makedirs(self.args.output_dir)
            return

        files_in_the_dir = os.listdir(self.args.output_dir)
        if len(files_in_the_dir) == 0 :
            # dir already empty
            return

        self.log(f"Overwriting all files in "
                 f"{self.args.output_dir}",'')
        # delete all old files in the output dir
        for file in files_in_the_dir:
            file_path = os.path.join(self.args.output_dir, file)
            with suppress(Exception):
                if os.path.isfile(file_path):
                    os.remove(file_path)
                elif os.path.isdir(file_path):
                    rmtree(file_path)

    def setup_output_dir(self):
        if self.args.output_dir:
            # -o is given
            self.prep_given_output_dir()
            output_dir: str = self.args.output_dir
        else:
            # -o isn't given, prep an output dir
            current_datetime = datetime.datetime.now()
            current_datetime = current_datetime.strftime('%Y-%m-%d-%H:%M:%S')
            output_dir = os.path.join('output/', f"{current_datetime}/")
            os.makedirs(output_dir)

        self.log(f"Storing output in: ", output_dir)
        return output_dir


    def log(self, green_txt, normal_txt, log_to_results_file=True, end="\n"):
        self.notify_observers(
            (normal_txt, green_txt, log_to_results_file, end)
            )


    def start_slips_parser(self):
        # this has to be the path of the sqlite3 db generated
        # by slips with all the labels and community IDs
        slips_db: str = self.args.slips_db
        self.log(f"Reading Slips db from: ", slips_db)
        assert os.path.isfile(slips_db), f"Slips DB should be a file, not a dir"
        SlipsParser(self.output_dir,
                    self.results_path,
                    slips_db=slips_db).parse()

    def start_suricata_parser(self):
        eve_file: str = self.args.eve_file
        self.log(f"Using suricata: ", eve_file)
        assert os.path.isfile(eve_file), f"Suricata eve.json should be " \
                                         f"a file, not a dir"
        # read suricata eve.json
        SuricataParser(self.output_dir,
                       self.results_path,
                       eve_file=eve_file).parse()

    def start_ground_truth_parser(self):
        self.log("Starting ground truth parser.", '')
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
        assert os.path.isabs(path), (f"Invalid path. {path} must be "
                                     f"absolute. Stopping.")
        assert os.path.exists(path), f"Path '{path}' doesn't exist"
        return True

    def start_parsers(self, print_stats_event):
        """
        runs each parser in a separate proc and returns when they're all done
        :param print_stats_event: the thread will set this event when it's
        done reading the ground truth flows and
        started reading slips and suricata flows so the print_stats
        thread can start printing
        """
        gt_parser: multiprocessing.Process = multiprocessing.Process(
            target=self.start_ground_truth_parser, args=( )
            )
        suricata_parser: multiprocessing.Process = multiprocessing.Process(
            target=self.start_suricata_parser, args=( )
            )
        slips_parser: multiprocessing.Process = multiprocessing.Process(
            target=self.start_slips_parser, args=( )
            )

        gt_parser.start()
        self.log(f"New process started for parsing: ",
                 'Ground Truth')
        gt_parser.join()

        # since we discard slips and suricata's flows based on
        # the ground truth flows,
        # we need to make sure we're done  reading them first
        suricata_parser.start()
        self.log(f"New process started for parsing: ",
                 'Suricata')

        slips_parser.start()
        self.log(f"New process started for parsing: ",
                 'Slips')

        print_stats_event.set()

        suricata_parser.join()
        slips_parser.join()
        self.log('', "-" * 30)


    def print_stats(self, print_stats_event):
        """
        thread that prints the total parsed flows by all parsers
         every once in a while
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
                  f"suricata: {self.db.get_flows_parsed('suricata')} ",
                  end='\r')
    
    def get_human_readable_datetime(self) -> str:
        now = datetime.datetime.now()
        return now.strftime("%A, %B %d, %Y %H:%M:%S")
    
    def read_configuration(self):
        config = ConfigurationParser()
        self.slips_version = config.slips_version()
        self.suricata_version = config.suricata_version()
        
    def add_metadata(self):
        """
        Adds tool versions and files used
        to metadata.txt in the outupt dir
        """
        metadata_file = os.path.join(self.output_dir, 'metadata.txt')
        self.log("Storing metadata in: ", metadata_file)

        with open(metadata_file, 'w') as metadata:
            metadata.write(f"Timestamp: "
                           f"{self.get_human_readable_datetime()}\n\n"
                           f"Used cmd: {' '.join(sys.argv)}\n\n"
                           f"Slips version: {self.slips_version} \n\n"
                           f"Suricata version: {self.suricata_version}\n\n"
                           f"Ground truth: "
                           f"{self.args.ground_truth_dir or self.args.ground_truth_file}\n"
                           f"Slips DB: {self.args.slips_db}\n\n"
                           f"Suricata file: {self.args.eve_file}\n\n"
                           f"Output directory: {self.output_dir}\n\n")

    def print_discarded_flows_and_tws(self, tool: str):
        """
        print the flows parsed, discarded and
        actual flows taken into consideration in the calculations by the given
        tool
        :param tool: slips or suricata
        """
        parsed_flows: int = self.db.get_flows_parsed(tool)
        discarded_flows: int = self.db.get_discarded_flows(tool)
        discarded_tws: int = self.db.get_discarded_timewindows(tool)

        self.log(f"Total read flows by {tool} "
                 f"(doesn't include discarded flows): {parsed_flows}  -- "
                 f"Discarded flows: {discarded_flows} -- "
                 f"Discarded timewindows: {discarded_tws}", '')

    def validate_gt(self):
        # this should always be a labeled zeek json dir
        if self.args.ground_truth_dir:
            ground_truth_dir: str = self.args.ground_truth_dir
            if self.validate_path(ground_truth_dir):
                self.log(f"Using ground truth dir: ", ground_truth_dir)
            assert os.path.isdir(ground_truth_dir),\
                f"Invalid dir {ground_truth_dir}. ground truth has to be a dir"

        elif self.args.ground_truth_file:
            ground_truth_file: str = self.args.ground_truth_file
            if self.validate_path(ground_truth_file):
                self.log(f"Using ground truth file: ", ground_truth_file)
            assert os.path.isfile(self.args.ground_truth_file), \
                f"Invalid file given with -gtf {self.args.ground_truth_file}. "
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

        #todo update this method and test it
        for tool in ('slips', 'suricata'):
            # dont pass the calc lists with actual and predicted data
            # as the cm is already calculated
            calc = Calculator(tool, self.output_dir)
            calc.metrics = cm
            calc.calc_all_metrics()
            self.log(' ', ' ', log_to_results_file=False)



    def handle_per_tw_comparison(self):
        #TODO move this to per tw class

        comparer = PerTimewindow(self.output_dir)

        self.log('', "-" * 30)
        self.log("Comparison method: ", comparer.name)
        self.log(' ', ' ', log_to_results_file=False)
        # TODO what to log per tw?

        # now apply this method to all supported tools
        for tool in self.supported_tools:
            calc = Calculator(tool, self.output_dir)
            for row in  self.db.get_all_labels_per_all_tws(tool):
                # each row is (ip, tw , gt_label, tool_label)
                ip, tw , gt_label, tool_label = row
                cm: dict = calc.get_confusion_matrix(
                    [(gt_label, tool_label)], log=False)
                self.db.store_performance_errors_per_tw(ip, tw, tool, cm)

        comparer.print_stats()
        
    def validate_given_paths(self):
        for path in (self.args.slips_db, self.args.eve_file):
            self.validate_path(path)
        self.validate_gt()
        
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

            stats_thread = Thread(target=self.print_stats,
                                  args=(print_stats_event,),
                                  daemon=True)
            stats_thread.start()
            self.validate_given_paths()
            self.start_parsers(print_stats_event)
            # now that the parses ended don't print more stats
            self.stop_stats_thread = True
            stats_thread.join()


            self.log(' ', ' ', log_to_results_file=False)
            self.log('', "-" * 30, log_to_results_file=False)
            self.log(f"Total flows read by parsers (doesn't include "
                     f"discarded flows): ",'')
            self.db.print_table('flows_count')


            self.log(' ', ' ')
            self.log("Flows are discarded when they're found in a "
                     "tool but not in the ground truth", '')
            for tool in self.supported_tools:
                self.print_discarded_flows_and_tws(tool)

            # before calculating anything, fill out the missing labels with benign
            self.db.fill_null_labels()

            self.log(f"Done. For labels db check: ", self.output_dir)

            self.log(' ', ' ', log_to_results_file=False)

            FlowByFlow(self.output_dir).handle_flow_by_flow_comparison()
            PerTimewindow(self.output_dir).handle_per_tw_comparison()

        self.db.close()

        analysis_time = time() - self.starttime
        self.log(f"Analysis time: ",f"{analysis_time/60} mins")



if __name__ == "__main__":
    Main().main()
