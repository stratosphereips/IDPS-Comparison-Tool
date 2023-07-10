# Installation
pip3 install -r requirements.txt

# Usage 
python3 main.py -s <slips input> -e <eve.json of suricata> -g <ground_truth_labeled_zeek_dir>

# requirements
specify the full path to slips installation dir in slips.conf

# How it works

The output of this tool is a sqlite db with 1 table
each row in this table should have the following
flow community_id, ground_truth label, suricata label, slips_label


The sqlite db created by this tool is stored in a subdir in the output/ dir
for example
output/zeek_dir_ground_truth-2023-07-10-14:04:16

This tool starts slips and gives it the input file specified by the -s param
Slips should only be started given a zeek dir or a pcap (for now)

