import logging
import multiprocessing.util

class PluginFormatter(logging.Formatter):
    """Custom logger to colorize messages."""

    COLOR_RED = 31
    COLOR_GREEN = 32
    COLOR_YELLOW = 33
    COLOR_BLUE = 34
    COLOR_PURPLE = 35

    LOG_COLORS = {
        logging.DEBUG: COLOR_BLUE,
        logging.INFO: COLOR_GREEN,
        logging.WARNING: COLOR_YELLOW,
        logging.ERROR: COLOR_RED,
        logging.CRITICAL: COLOR_PURPLE,
    }

    def __init__(self, fmt=None, datefmt=None):
        logging.Formatter.__init__(self, fmt, datefmt)

    def __colorize(self, s, color=COLOR_RED):
        """Colorize a characters string."""
        retval = chr(0x1B) + "[0;%dm" % color + str(s) + chr(0x1B) + "[0m"
        return retval

    def format(self, record):
        """A custom format handler to colorize log level names."""
        colorno = PluginFormatter.LOG_COLORS.get(record.levelno, None)
        if colorno is not None:
            record.levelname = self.__colorize(record.levelname, colorno)
        msg = super(PluginFormatter, self).format(record)
        return msg

def customize_logger(logger, fmt=multiprocessing.util.DEFAULT_LOGGING_FORMAT):
    assert len(logger.handlers) == 1
    handler = logging.StreamHandler()
    formatter = PluginFormatter(fmt)
    handler.setFormatter(formatter)
    logger.handlers[0] = handler

def get_logging():
    return logging

def init_logging(loglevel = logging.INFO):
    """Initialize the logging subsystem, at the specified level."""
    # Set the proper verbosity level
    if  isinstance(loglevel, int):
        numeric_loglevel = loglevel
    else:
        numeric_loglevel = getattr(logging, loglevel.upper(), None)
    logging.basicConfig(level=numeric_loglevel)

    # Install our own logging handler
    log_format = "[%(asctime)s] %(levelname)s : %(message)s"
    customize_logger(logging.root, fmt=log_format)