# Installation
pip3 install -r requirements.txt

# Usage 
python3 main.py -s <slips_db_abs_path> -e <eve.json_abs_path> -g <ground_truth_labeled_zeek_dir>

for testing use this command:

python3 main.py -g /home/alya/Desktop/IDPS-Comparison-Tool/dataset/zeek_dir_ground_truth -s /home/alya/Desktop/IDPS-Comparison-Tool/dataset/sample_slips_db.sqlite -e /home/alya/Desktop/IDPS-Comparison-Tool  


# requirements
specify the full path to slips installation dir in slips.conf

# How it works

The output of this tool is a sqlite db with 1 table
each row in this table should have the following
flow community_id, ground_truth label, suricata label, slips_label


The sqlite db created by this tool is stored in a subdir in the output/ dir
for example
output/zeek_dir_ground_truth-2023-07-10-14:04:16

slips now stores the community id for each conn.log flow stored in the sqlite db
the table with the community id and label in slips is called 'flows' inside the flows.sqlite db
this toold read only this table with the labels and community id and stores the labels in it's own db stored in output/db.sqlite



# Keep in mind
now this tool does not give remotely accurate metrics because it needs to be tested on the same data
here's what we need to do
have 1 pcap
have ground truth labels for all of tis' flows in the form of zeek tabs 
give it to slips and get the labels
give it to suricata and get the labels
give the above 3 labels to this tool
