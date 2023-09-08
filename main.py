import os.path
import sys
from threading import Thread
from parsers.config import ConfigurationParser
from parsers.suricata import SuricataParser
from database.sqlite_db import SQLiteDB
from parsers.arg_parser import ArgsParser
from parsers.slips import SlipsParser
from parsers.ground_truth import GroundTruthParser
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

def start_slips_parser(output_dir):
    # this has to be the path of the sqlite3 db generated by slips with all the labels and community IDs
    slips_db: str = args.slips_db
    if validate_path(slips_db):
        log(f"Reading Slips db from: ", slips_db)
    assert os.path.isfile(slips_db), f"Slips DB should be a file, not a dir"
    SlipsParser(output_dir, slips_db=slips_db).parse()

def start_suricata_parser(output_dir):
    eve_file: str = args.eve_file
    if validate_path(eve_file):
        log(f"Using suricata: ", eve_file)
    assert os.path.isfile(eve_file), f"Suricata eve.json should be a file, not a dir"
    # read suricata eve.json
    SuricataParser(output_dir, eve_file=eve_file).parse()

def start_ground_truth_parser(output_dir):
    if args.ground_truth_dir:
        # read the ground truth and store it in the db
        GroundTruthParser(
            output_dir,
            ground_truth=ground_truth_dir,
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

def start_parsers(output_dir):
    """
    runs each parser in a separate proc and returns when they're all done
    """
    gt_parser: multiprocessing.Process = multiprocessing.Process(target=start_ground_truth_parser, args=(output_dir, ))
    suricata_parser: multiprocessing.Process = multiprocessing.Process(target=start_suricata_parser, args=(output_dir, ))
    slips_parser: multiprocessing.Process = multiprocessing.Process(target=start_slips_parser, args=(output_dir, ))

    gt_parser.start()
    log(f"New process started for parsing: ", 'Ground Truth')

    suricata_parser.start()
    log(f"New process started for parsing: ", 'Suricata')

    slips_parser.start()
    log(f"New process started for parsing: ", 'Slips')

    gt_parser.join()
    suricata_parser.join()
    slips_parser.join()


def print_stats(output_dir):
    """
    thread that prints the total parsed flows by all parsers every once in a while
    :param db:
    :return:
    """
    db = SQLiteDB(output_dir)

    global stop_stats_thread
    while not stop_stats_thread:
        sleep(5)
        current_datetime = datetime.datetime.now()
        now = current_datetime.strftime('%Y-%m-%d %H:%M:%S')
        print(f"{now} - Total parsed flows by "
              f"slips: {db.get_flows_parsed('slips')} "
              f"suricata: {db.get_flows_parsed('suricata')} "
              f"ground_truth: {db.get_flows_parsed('ground_truth')}", end='\r')


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

if __name__ == "__main__":

    starttime = time()
    args = ArgsParser().args

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

    output_dir = setup_output_dir()

    add_metadata(output_dir, args)

    db = SQLiteDB(output_dir)

    stats_thread = Thread(target=print_stats, args=(output_dir,), daemon=True)
    stats_thread.start()

    start_parsers(output_dir)
    # now that the parses ended don't print more stats
    stop_stats_thread = True
    stats_thread.join()

    log(f"Total flows read by parsers: ",'')
    db.print_table('flows_count')

    # before calculating anything, fill out the missing labels with benign
    db.fill_null_labels()

    log(f"Done. For labels db check: ", output_dir)

    print()
    calc = Calculator(output_dir)
    # Print confusion matrix for slips
    calc.get_confusion_matrix('slips')

    print()
    # Print confusion matrix for suricata
    calc.get_confusion_matrix('suricata')

    print()
    calc.FPR('slips')
    calc.FPR('suricata')

    print()
    calc.recall('slips')
    calc.recall('suricata')

    print()
    calc.precision('slips')
    calc.precision('suricata')

    print()
    calc.F1('slips')
    calc.F1('suricata')
    analysis_time = time() - starttime

    print(f"Analysis time: {analysis_time/60} mins")

    db.close()