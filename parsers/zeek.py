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

    def extract_fields(self, filename: str):
        """
        extracts the label and community id from each flow and stores them in the db
        :param filename: the name of the logfile without the path, for example conn.log
        """
        # get the full path of the given log file
        fullpath = os.path.join(self.zeek_dir, filename)

        with open(fullpath, 'r') as f:
            while line := f.readline():

                try:
                    line = json.loads(line)
                except json.decoder.JSONDecodeError:
                    print(f"Error loading line: \n{line}")

                # extract fields
                fields = {
                   'community_id': line.get('community_id', ''),
                   'label':  line.get('label', '')
                   }
               #TODO store this in the db

        return fields

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




