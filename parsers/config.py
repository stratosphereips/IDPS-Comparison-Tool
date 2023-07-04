import configparser

class ConfigurationParser:
    def __init__(self, filename):
        self.conf = self.read_config(filename)

    def read_config(self, filename):
        config = configparser.ConfigParser()
        config.read(filename)
        return config

    def get(self, section, key, default_value=None):
        try:
            return self.conf.get(section, key)
        except:
            return default_value
    def get_tw_width(self) -> float:
        try:
            twid_width = self.conf.get('Params', 'time_window_width')
        except (
            configparser.NoOptionError,
            configparser.NoSectionError,
            NameError,
            ValueError
        ):
            # There is a conf, but there is no option,
            # or no section or no configuration file specified
            twid_width = 3600

        try:
            twid_width = float(twid_width)
        except ValueError:
            # Its not a float
            if 'only_one_tw' in twid_width:
                # Only one tw. Width is 10 9s, wich is ~11,500 days, ~311 years
                twid_width = 9999999999
        return twid_width

