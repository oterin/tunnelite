import logging

# fetch log level from values.json or env
from server import config
from pythonjsonlogger.jsonlogger import JsonFormatter

# create a logger instance that can be imported by other modules
log = logging.getLogger("tunnelite")

# set the log level from an environment variable, defaulting to info
log_level = config.get("LOG_LEVEL", "INFO").upper()
log.setLevel(log_level)

# create a handler to output log records to the console (stdout)
logHandler = logging.StreamHandler()

# use the new, correct jsonformatter class and a modern format string
# this format ensures that standard log attributes are included along with any extra data.
formatter = JsonFormatter(
    '%(asctime)s %(name)s %(levelname)s %(message)s'
)

# set the json formatter for the handler
logHandler.setFormatter(formatter)

# add the handler to the logger, ensuring it's only added once.
if not log.handlers:
    log.addHandler(logHandler)
