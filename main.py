import os.path

from parsers.config import ConfigurationParser
from database.sqlite_db import SQLiteDB
from parsers.arg_parser import ArgsParser
from contextlib import suppress
from shutil import rmtree
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
        print(f"Overwriting all files in {output_dir}")
        for file in os.listdir(output_dir):
            file_path = os.path.join(output_dir, file)
            with suppress(Exception):
                if os.path.isfile(file_path):
                    os.remove(file_path)
                elif os.path.isdir(file_path):
                    rmtree(file_path)
    else:
        os.makedirs(output_dir)
    print(f"Storing output in {output_dir}")
    return output_dir


if __name__ == "__main__":
    # Read the configuration file
    config = ConfigurationParser('config.ini')
    twid_width = config.get_tw_width()
    args = ArgsParser().args

    # TODO uncomment assertions when we have some files to test with
    zeek_dir: str = args.zeek_dir
    # assert os.path.exists(zeek_dir)

    eve_file: str = args.eve_file
    # assert os.path.exists(zeek_dir)

    ground_truth_dir: str = args.ground_truth_dir
    # assert os.path.exists(ground_truth_dir)

    output_dir = setup_output_dir(zeek_dir)
