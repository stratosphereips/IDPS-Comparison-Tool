import yaml

class ConfigurationParser:
    def __init__(self, filename):
        self.conf = self.load_config(filename)

    def load_config(self, file_path):
        with open(file_path, 'r') as file:
            config = yaml.safe_load(file)
        return config

    def get(self, key, val,default_value=None):
        try:
            return self.conf[key][val]
        except KeyError:
            return default_value


    def slips_version(self):
        return self.get("Slips",'version')

    def suricata_version(self):
        return self.get("Suricata",'version')

    def timewindow_width(self):
        return self.get("Params", 'timewindow_width', 3600)