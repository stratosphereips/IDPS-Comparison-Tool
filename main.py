
from parsers.config import ConfigurationParser
from database.sqlite_db import SQLiteDB
from parsers.arg_parser import ArgsParser

if __name__ == "__main__":
    # Read the configuration file
    config = ConfigurationParser('config.ini')
    twid_width = config.get_tw_width()
    args = ArgsParser().args

    # print(f"@@@@@@@@@@@@@@@@ {args.zeek_dir}")
    # print(f"@@@@@@@@@@@@@@@@ {args.eve_file}")
    # print(f"@@@@@@@@@@@@@@@@ {args.ground_truth_dir}")

