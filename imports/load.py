import configparser


def load_configuration():
    """Load configuration from config.ini file."""
    config = configparser.ConfigParser()
    config.read("config.ini")

    defaults = config["Defaults"]
    interval = defaults.getfloat("interval", 0.1)
    udp = defaults.getboolean("udp", False)

    return interval, udp