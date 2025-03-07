import os
import sys
from threading import Thread
from contextlib import suppress
from shutil import rmtree
import datetime
import multiprocessing
from time import time, sleep
from typing import (
    Tuple,
    Optional,
    )

from git import Repo

from modes.tools_parser import (
    ParserHandler,
    )
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
from utils.metadata_handler import MetadataHandler


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
        self.errors_file_path = os.path.join(self.output_dir, 'errors.log')
        # init the logger
        self.logger = Logger(self.name, self.output_dir)
        self.add_observer(self.logger)
        
        self.read_configuration()

        self.db = SQLiteDB(self.output_dir)
        self.metadata_handler = MetadataHandler(self)
        self.metadata_handler.add_metadata()
        self.log(f"Storing results in: ", self.results_path)
        self.log(f"Logging errors to: ", self.errors_file_path)

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
        """
        create a new output dir for storing the results of this run.
        either using the given -o or a new one with the date and time
        :return:
        """
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


    def log(self, colored_txt, normal_txt, log_to_results_file=True,
            end="\n", error=False):
        self.notify_observers(
            (normal_txt, colored_txt, log_to_results_file, end, error)
            )


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
            to_print = f"{now} - Total parsed flows by "
            for tool in self.supported_tools:
                to_print += f"{tool}: {self.db.get_flows_parsed('slips')} "
            print(to_print, end='\r')
    

    
    def read_configuration(self):
        config = ConfigurationParser()
        self.slips_version = config.slips_version()
        self.suricata_version = config.suricata_version()
        

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

        
    def main(self):
        if self.args.confusion_matrix_db:
            """
            given a db with pre-calculated TP, TN FP, FN for each tool
            continue analysis from here
            """
            self.read_cm_db()

        else:
            # used to tell the print_stats thread to start
            print_stats_event = multiprocessing.Event()
            
            tools_parser = ParserHandler(
                self.output_dir,
                self.results_path,
                print_stats_event
                )
            self.supported_tools: Tuple[str] = (
                tools_parser.get_supported_tools()
            )
            stats_thread = Thread(target=self.print_stats,
                                  args=(print_stats_event,),
                                  daemon=True)
            stats_thread.start()
            
            all_good: bool = tools_parser.start_parsers()
            if not all_good:
                self.log("",
                         "Problem occurred with parsers. Stopping.",
                         error=True)
                return
            
            # now that the parsers ended don't print more stats
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
            
            FlowByFlow(self.output_dir,
                       self.supported_tools
                       ).compare()
            PerTimewindow(self.output_dir,
                          self.supported_tools
                          ).compare()

        self.db.close()
        end_time: str = self.metadata_handler.add_end_time()
        dt_object = datetime.datetime.strptime(
            end_time, "%A, %B %d, %Y %H:%M:%S")
        epoch_end_time = dt_object.timestamp()
        analysis_time = epoch_end_time - self.starttime
        self.metadata_handler.add_analysis_time(analysis_time)
        self.log(f"Analysis time: ",f"{analysis_time/60} mins")



if __name__ == "__main__":
    Main().main()
