
from parsers.config import ConfigurationParser


if __name__ == "__main__":
    # Read the configuration file
    config = ConfigurationParser('config.ini')
    twid_width = config.get_tw_width()
