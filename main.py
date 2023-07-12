import os.path
import sys
from parsers.config import ConfigurationParser
from parsers.suricata import SuricataParser
from database.sqlite_db import SQLiteDB
from parsers.arg_parser import ArgsParser
from parsers.slips import SlipsParser
from parsers.ground_truth import GroundTruthParser
from contextlib import suppress
from shutil import rmtree
from termcolor import colored
import datetime


def setup_output_dir(zeek_dir):
    output_dir = 'output/'

    zeek_dir = os.path.basename(zeek_dir)
    output_dir = os.path.join(output_dir, zeek_dir)

    current_datetime = datetime.datetime.now()
    output_dir += '-' + current_datetime.strftime('%Y-%m-%d-%H:%M:%S')

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

def start_slips_parser():
    # this has to be the path of the sqlite3 db generated by slips with all the labels and community IDs
    slips_db: str = args.slips_db
    if validate_path(slips_db):
        log(f"Reading SLips db from: ", slips_db)
    assert os.path.isfile(slips_db), f"Slips DB should be a file, not a dir"
    SlipsParser(slips_db, db).parse()

def start_suricata_parser():
    eve_file: str = args.eve_file
    if validate_path(eve_file):
        log(f"Using suricata: ", eve_file)
    assert os.path.isfile(eve_file), f"Suricata eve.json should be a file, not a dir"
    # read suricata eve.json
    SuricataParser(eve_file, db).parse()

def start_ground_truth_parser():
    # read the ground truth and store it in the db
    GroundTruthParser(ground_truth_dir, db).parse()

def validate_path(path):
    if not os.path.isabs(path):
        log(f"Invalid Path. {path} must be absolute. Stopping.", '')
        sys.exit()
    assert os.path.exists(path), f"Path '{path}' doesn't exist"
    return True

if __name__ == "__main__":
    # Read the configuration file
    config = ConfigurationParser('config.ini')
    twid_width: float = config.get_tw_width()
    args = ArgsParser().args

    # this should always be a labeled zeek json dir
    ground_truth_dir: str = args.ground_truth_dir
    if validate_path(ground_truth_dir):
        log(f"Using ground truth dir: ", ground_truth_dir)
    assert os.path.isdir(ground_truth_dir), f"Invalid dir {ground_truth_dir}. ground truth has to be a dir"

    output_dir = setup_output_dir(ground_truth_dir)

    db = SQLiteDB(output_dir)

    start_suricata_parser()

    start_slips_parser()

    start_ground_truth_parser()
    log(f"Total flows read by parsers: ",'')
    db.print_table('flows_count')
    log(f"Done. For labels db check: ", output_dir)