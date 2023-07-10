import argparse


class ArgsParser:
    parser = argparse.ArgumentParser(description='Process command line arguments.')
    parser.add_argument('-s', '--slips_input_file', dest='slips_input_file', help='PCAP or zeek dir for Slips')
    parser.add_argument('-e', '--eve', dest='eve_file', help='eve.json file of Suricata')
    parser.add_argument('-g', '--gt', dest='ground_truth_dir', help='Ground truth labeled Zeek directory')
    args = parser.parse_args()
