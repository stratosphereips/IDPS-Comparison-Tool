import os
import json

# these are the files that slips doesn't read
IGNORED_LOGS = {
    'capture_loss',
    'loaded_scripts',
    'packet_filter',
    'stats',
    'ocsp',
    'reporter',
    'x509',
    'pe',
    'mqtt_publish',
    'mqtt_subscribe',
    'mqtt_connect',
    'analyzer',
    'ntp',
    'radiuss',
    'sip',
    'syslog'
}
class ZeekParser:
    def __init__(self, zeek_dir: str):
        self.zeek_dir: str = zeek_dir

    def parse_dir(self):
        """
        parses each log file in self.zeek_dir
        :return:
        """
        for file in os.listdir(self.zeek_dir):
            if not os.path.isfile(file):
                continue

            # skip ignored logs
            base_filename, ext = os.path.splitext(file)
            if base_filename in IGNORED_LOGS:
                continue

            # extract fields and store them in the db
            self.extract_fields(file)




