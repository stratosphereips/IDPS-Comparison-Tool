# Installation

pip3 install -r requirements.txt

# Usage 

python3 main.py -s <slips_db_abs_path> -e <eve.json_abs_path> -g <ground_truth_labeled_zeek_dir_abs_path>

for testing use this command:

***Example of using labeled ground truth file***

python3 main.py -gtd $(pwd)/dataset/CTU-Malware-Capture-Botnet-4/ground_truth/ -s $(pwd)/dataset/CTU-Malware-Capture-Botnet-4/slips/flows.sqlite -e $(pwd)/dataset/CTU-Malware-Capture-Botnet-4/suricata/eve.json  

***Example of using ground truth dir***

python3 main.py -gtf $(pwd)/dataset/CTU-Malware-Capture-Botnet-4/ground_truth/conn.log.labeled -s $(pwd)/dataset/CTU-Malware-Capture-Botnet-4/slips/flows.sqlite -e $(pwd)/dataset/CTU-Malware-Capture-Botnet-4/suricata/eve.json  


# How it works

## comparison tool output

The output of this tool is:

1. a sqlite db with 1 table
2. the metrics printed in the CLI at the end of the analysis

each row in the output table should have the following:

flow community_id, ground_truth_label, suricata_label, slips_label


The sqlite db created by this tool is stored in a subdir in the output/ dir
for example
```output/2023-07-10-14:04:16```

## slips output 

Slips now stores the community id for each conn.log flow in the sqlite db

The SQL table with the community id and label in Slips is called 'flows' inside the ```flows.sqlite``` db

This tool reads the ```flows.sqlite``` db, extracts the labels and community ids, and stores the them in its' own db stored in ```output/<date-time>/db.sqlite```

## suricata output

Suricata's used output file is eve.json with the 'community_id' field

if the field event_type is set to 'alert', this tool marks this flow as malicious by suricata.

After this tool parses the ground truth, slips and suricata's output, it uses metrics/calculator.py to calc the metrics and display them in the CLI


# Limitations

* the labels in ground truth zeek dir have to be 'Malicious' or 'Benign' only. if any other label is present this tool will consider it "benign"
* ground truth files and dir shouldn't have the community id. this tool calculates it on the fly
* ground truth dirs can either be json or tab separated zeek dir or conn.log file

* all paths given as parameters to this tool must be absolute paths.
* if any flow doesn't have a label by suricata or slips, this tool considers the flow as benign 

* slips now labels conn.log flows only, just like zeek does when community_id is enabled as a plugin
