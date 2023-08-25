import os
from pathlib import Path
import shutil

def mkdirr(path:str):
	path = Path(path)
	path.mkdir(parents=True, exist_ok=True)	

pcap = '/home/alya/Desktop/IDPS-Comparison-Tool/Dataset/CTU-SME-11-Honeypot-Minicomputer-RaspberryPi-Gen3-20-2023-02-21/193.105.134.95.pcap'
output_dir = '/home/alya/Desktop/IDPS-Comparison-Tool/Dataset/CTU-SME-11-Honeypot-Minicomputer-RaspberryPi-Gen3-20-2023-02-21'
slips = '/home/alya/Desktop/StratosphereLinuxIPS'

suricata_path = os.path.join(output_dir, 'suricata')
slips_path = os.path.join(output_dir, 'slips')
ground_truth_path = os.path.join(output_dir, 'ground_truth')


mkdirr(output_dir)
mkdirr(suricata_path)
mkdirr(ground_truth_path)
mkdirr(slips_path)



os.chdir(suricata_path)
suricata_cmd = f'suricata -r {pcap}'
os.system(suricata_cmd)



os.chdir(ground_truth_path)
zeek_cmd = f'zeek -C -r {pcap}  tcp_inactivity_timeout=60mins tcp_attempt_delay=1min'
os.system(zeek_cmd)

# run labeler
labeler_cmd = f'python3 /home/alya/Desktop/netflowlabeler/netflowlabeler.py -c /home/alya/Desktop/netflowlabeler/labels.config -f {os.path.join(ground_truth_path, "conn.log")}'
os.system(labeler_cmd)

print(f"going to slips : {slips}")
os.chdir(slips)
slips_cmd = f'./slips.py -e 1 -f {pcap} -o alia'
os.system(slips_cmd)

slips_output_path = os.path.join(slips, 'alia/flows.sqlite')
shutil.copyfile(slips_output_path, os.path.join(slips_path, 'flows.sqlite'))
print(f"ok..  go to {output_dir}")



print(f"python3 main.py -gtf {os.path.join(ground_truth_path, 'conn.log.labeled')} -s  {slips_output_path} -e {os.path.join(suricata_path, 'eve.json')} ")





