# Installation
pip3 install -r requirements.txt

# Usage 
python3 main.py -s <slips_db_abs_path> -e <eve.json_abs_path> -g <ground_truth_labeled_zeek_dir_abs_path>

for testing use this command:

python3 main.py -g /home/alya/Desktop/IDPS-Comparison-Tool/dataset/CTU-Malware-Capture-Botnet-4/ground_truth -s /home/alya/Desktop/IDPS-Comparison-Tool/dataset/CTU-Malware-Capture-Botnet-4/slips/flows.sqlite -e /home/alya/Desktop/IDPS-Comparison-Tool/dataset/CTU-Malware-Capture-Botnet-4/suricata/eve.json


# requirements
specify the full path to slips installation dir in slips.conf

# How it works

## comparision tool output

The output of this tool is a sqlite db with 1 table + the metrics printed in the cli at the end of this tools analysis
each row in this table should have the following
flow community_id, ground_truth label, suricata label, slips_label


The sqlite db created by this tool is stored in a subdir in the output/ dir
for example
output/zeek_dir_ground_truth-2023-07-10-14:04:16

## slips output 
slips now stores the community id for each conn.log flow stored in the sqlite db
the table with the community id and label in slips is called 'flows' inside the flows.sqlite db
this toold read only this table with the labels and community id and stores the labels in it's own db stored in output/db.sqlite

## suricata output
suricata's used output file is eve.json with the 'community_id' field
if the field event_type is set to 'alert', this tool marks this flow as malicious by suricata.


# Limitations

* the labels in ground truth zeek dir has to be 'Malicious' or 'Benign' only. if any other label is present this tool will consider it benign
* all ground truth flows must have a community id
* ground truth dir can either be json or tab separated zeek dir. it can't be 1 conn.log

* all paths given as param to this tool must be absolute paths
* if any flow doesn't have a label by suricata or slips, this tool considers the flow as benign 

* slips now labels conn.log flows only, just like zeek does when community_id is enabled as a plugin
