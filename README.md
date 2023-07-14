# Installation
pip3 install -r requirements.txt

# Usage 
python3 main.py -s <slips_db_abs_path> -e <eve.json_abs_path> -g <ground_truth_labeled_zeek_dir_abs_path>

for testing use this command:

Example of using labeled ground truth file

python3 main.py -gtd /home/alya/Desktop/IDPS-Comparison-Tool/dataset/CTU-Malware-Capture-Botnet-4/ground_truth -s /home/alya/Desktop/IDPS-Comparison-Tool/dataset/CTU-Malware-Capture-Botnet-4/slips/flows.sqlite -e /home/alya/Desktop/IDPS-Comparison-Tool/dataset/CTU-Malware-Capture-Botnet-4/suricata/eve.json

example of using ground truth dir

python3 main.py -gtf /home/alya/Desktop/IDPS-Comparison-Tool/dataset/CTU-Malware-Capture-Botnet-4/ground_truth/conn.log.labeled -s /home/alya/Desktop/IDPS-Comparison-Tool/dataset/CTU-Malware-Capture-Botnet-4/slips/flows.sqlite -e /home/alya/Desktop/IDPS-Comparison-Tool/dataset/CTU-Malware-Capture-Botnet-4/suricata/eve.json


# How it works

## comparision tool output

The output of this tool is a sqlite db with 1 table AND the metrics printed in the CLI at the end of this tool's analysis
each row in this table should has the following
flow community_id, ground_truth label, suricata label, slips_label


The sqlite db created by this tool is stored in a subdir in the output/ dir
for example
output2023-07-10-14:04:16

## slips output 
slips now stores the community id for each conn.log flow in the sqlite db
the table with the community id and label in slips is called 'flows' inside the flows.sqlite db
this tool reads only this flows.sqlite table with the labels and community id and stores the labels in it's own db stored in output/<date-time>/db.sqlite

## suricata output
suricata's used output file is eve.json with the 'community_id' field
if the field event_type is set to 'alert', this tool marks this flow as malicious by suricata.


After this tool parses groudn truth, slips and suricata's output, it uses metrics/calculator.py to calc metrics and display them in the cli


# Limitations

* the labels in ground truth zeek dir have to be 'Malicious' or 'Benign' only. if any other label is present this tool will consider it benign
* ground truth files and dir don't shouldn't have the community id. this tool calculates it on the fly
* ground truth dir can either be json or tab separated zeek dir or conn.log file

* all paths given as param to this tool must be absolute paths
* if any flow doesn't have a label by suricata or slips, this tool considers the flow as benign 

* slips now labels conn.log flows only, just like zeek does when community_id is enabled as a plugin
