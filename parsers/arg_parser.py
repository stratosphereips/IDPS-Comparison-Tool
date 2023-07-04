import argparse


class ArgsParser:
    parser = argparse.ArgumentParser(description='Process command line arguments.')
    parser.add_argument('-d', '--zeekdir', dest='zeek_dir', help='Zeek directory for Slips')
    parser.add_argument('-e', '--eve', dest='eve_file', help='eve.json file of Suricata')
    parser.add_argument('-g', '--gt', dest='ground_truth_dir', help='Ground truth labeled Zeek directory')
    args = parser.parse_args()
