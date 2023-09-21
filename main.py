import os.path
import sys
from threading import Thread
from typing import Tuple, List
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

stop_stats_thread = False


def setup_output_dir():
    output_dir = 'output/'
    current_datetime = datetime.datetime.now()
    output_dir = os.path.join(output_dir, current_datetime.strftime('%Y-%m-%d-%H:%M:%S') + '/')

    # todo add support for -o
    # delete all old files in the output dir
    if os.path.exists(output_dir):
        # this will be used when -o is supported
        log(f"Overwriting all files in {output_dir}",'')
        for file in os.listdir(output_dir):
            file_path = os.path.join(output_dir, file)
            with suppress(Exception):
                if os.path.isfile(file_path):
                    os.remove(file_path)
                elif os.path.isdir(file_path):
                    rmtree(file_path)
    else:
        os.makedirs(output_dir)
    log(f"Storing output in: ", output_dir)
    return output_dir


def log(green_txt, normal_txt):
    normal_txt = str(normal_txt)
    green_txt = str(green_txt)

    print( colored("[Main] ", 'blue')+ colored(green_txt,'green') + normal_txt)

def start_slips_parser(args, output_dir):
    # this has to be the path of the sqlite3 db generated by slips with all the labels and community IDs
    slips_db: str = args.slips_db
    if validate_path(slips_db):
        log(f"Reading Slips db from: ", slips_db)
    assert os.path.isfile(slips_db), f"Slips DB should be a file, not a dir"
    SlipsParser(output_dir, slips_db=slips_db).parse()

def start_suricata_parser(args, output_dir):
    eve_file: str = args.eve_file
    if validate_path(eve_file):
        log(f"Using suricata: ", eve_file)
    assert os.path.isfile(eve_file), f"Suricata eve.json should be a file, not a dir"
    # read suricata eve.json
    SuricataParser(output_dir, eve_file=eve_file).parse()

def start_ground_truth_parser(args, output_dir):
    if args.ground_truth_dir:
        # read the ground truth and store it in the db
        GroundTruthParser(
            output_dir,
            ground_truth=args.ground_truth_dir,
            ground_truth_type='dir',
            ).parse()

    elif args.ground_truth_file:
        # read the ground truth and store it in the db
        GroundTruthParser(
            output_dir,
            ground_truth=args.ground_truth_file,
            ground_truth_type='file',
            ).parse()


def validate_path(path):
    """make sure this path is abs and exists"""
    if not os.path.isabs(path):
        log(f"Invalid Path. {path} must be absolute. Stopping.", '')
        sys.exit()
    assert os.path.exists(path), f"Path '{path}' doesn't exist"
    return True

def start_parsers(args, output_dir, print_stats_event):
    """
    runs each parser in a separate proc and returns when they're all done
    :param print_stats_event: the thread will set this event when it's done reading the ground truth flows and
    started reading slips and suricata flows so the print_stats thread can start printing
    """
    gt_parser: multiprocessing.Process = multiprocessing.Process(target=start_ground_truth_parser, args=(args, output_dir, ))
    suricata_parser: multiprocessing.Process = multiprocessing.Process(target=start_suricata_parser, args=(args, output_dir, ))
    slips_parser: multiprocessing.Process = multiprocessing.Process(target=start_slips_parser, args=(args, output_dir, ))

    gt_parser.start()
    log(f"New process started for parsing: ", 'Ground Truth')
    gt_parser.join()

    # since we discard slips and suricata's flows based on the ground truth flows,
    # we need to make sure we're done  reading them first
    suricata_parser.start()
    log(f"New process started for parsing: ", 'Suricata')

    slips_parser.start()
    log(f"New process started for parsing: ", 'Slips')

    print_stats_event.set()

    suricata_parser.join()
    slips_parser.join()
    print('-' * 30)


def print_stats(output_dir, print_stats_event):
    """
    thread that prints the total parsed flows by all parsers every once in a while
    :param db:
    :return:
    """
    print_stats_event.wait()
    db = SQLiteDB(output_dir)

    global stop_stats_thread
    while not stop_stats_thread:
        sleep(5)
        current_datetime = datetime.datetime.now()
        now = current_datetime.strftime('%Y-%m-%d %H:%M:%S')
        print(f"{now} - Total parsed flows by "
              f"slips: {db.get_flows_parsed('slips')} "
              f"suricata: {db.get_flows_parsed('suricata')} ", end='\r')


def add_metadata(output_dir, args):
    """
    Adds tool versions and files used
    to metadata.txt in the outupt dir
    """
    metadata_file = os.path.join(output_dir, 'metadata.txt')
    log("Storing metadata in: ", metadata_file)

    # Read the configuration file
    config = ConfigurationParser('config.yaml')
    slips_version = config.slips_version()
    suricata_version = config.suricata_version()

    with open(metadata_file, 'w') as metadata:
        metadata.write(f"Slips version: {slips_version} \n"
                       f"Suricata version: {suricata_version}\n\n"
                       f"Ground truth: "
                       f"{args.ground_truth_dir or args.ground_truth_file}\n"
                       f"Slips DB: {args.slips_db}\n"
                       f"Suricata file: {args.eve_file}\n")

def print_flows_parsed_vs_discarded(tool: str, db):
    """
    print the flows parsed, discarded and actual
    flows taken into consideration in the calculations by the given
    tool
    :param tool: slips or suricata
    """
    parsed_flows: int = db.get_flows_parsed(tool)
    discarded_flows: int = db.get_discarded_flows(tool)
    used_flows: int =  parsed_flows - discarded_flows
    if not discarded_flows:
        used_flows = parsed_flows

    log(f"Total read flows by {tool}: {parsed_flows}  -- Discarded flows: {discarded_flows} -- Flows used after discarding:"
        f" {used_flows}", '')

def validate_gt(args):
    # this should always be a labeled zeek json dir
    if args.ground_truth_dir:
        ground_truth_dir: str = args.ground_truth_dir
        if validate_path(ground_truth_dir):
            log(f"Using ground truth dir: ", ground_truth_dir)
        assert os.path.isdir(ground_truth_dir), f"Invalid dir {ground_truth_dir}. ground truth has to be a dir"

    elif args.ground_truth_file:
        ground_truth_file: str = args.ground_truth_file
        if validate_path(ground_truth_file):
            log(f"Using ground truth file: ", ground_truth_file)
        assert os.path.isfile(args.ground_truth_file), f"Invalid file given with -gtf {args.ground_truth_file}. "
    else:
        print("No ground truth file or dir was given. stopping.")
        sys.exit()


def read_cm_db(cm_db: str):
    """
    starts the confusion matrix db parser
    :param cm_db: confusion matrix db as read from the args (-cm)
    """
    log("Consusion matrix database parser started using:", cm_db)
    ConfusionMatrixDBParser(output_dir, db_path=cm_db).parse()

def main():
    starttime = time()
    args = ArgsParser().args


    output_dir = setup_output_dir()

    add_metadata(output_dir, args)


    db = SQLiteDB(output_dir)


    if args.confusion_matrix_db:
        """
        given a db with precalculated TP, tN FP, FN for each tool
        continue analysis from here
        """
        read_cm_db(args.confusion_matrix_db)
        # tODO add a main function
    else:

        validate_gt(args)

        # used to tell the print_stats thread to start
        print_stats_event = multiprocessing.Event()

        stats_thread = Thread(target=print_stats, args=(output_dir, print_stats_event,), daemon=True)
        stats_thread.start()

        start_parsers(args, output_dir, print_stats_event)
        # now that the parses ended don't print more stats
        stop_stats_thread = True
        stats_thread.join()

        print()
        print("-" * 30)
        log(f"Total flows read by parsers: ",'')
        db.print_table('flows_count')


    ###############################


    supported_tools = ('slips', 'suricata')

    print()
    for tool in supported_tools:
        print_flows_parsed_vs_discarded(tool, db)


    # before calculating anything, fill out the missing labels with benign
    db.fill_null_labels()

    log(f"Done. For labels db check: ", output_dir)


    print()

    supported_comparison_methods = (FlowByFlow, PerTimewindow)
    for comparison_method in supported_comparison_methods:
        # create an obj of the helper class sresponsible for handling this type of comparison
        comparer = comparison_method(output_dir)

        print('-' * 30)
        log("Comparison type: ", comparer.name)
        print()

        # now apply this method to all supported tools
        for tool in supported_tools:
            # get the actual and predicted labels by the tool using the
            # comparison method above
            actual, predicted = comparer.get_labels_lists(tool)
            calc = Calculator(tool, actual, predicted, output_dir)

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
            print()


    db.close()

    analysis_time = time() - starttime
    log(f"Analysis time: ",f"{analysis_time/60} mins")



if __name__ == "__main__":
    main()
