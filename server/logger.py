import logging
import os
from python_json_logger import jsonlogger

log = logging.getLogger("tunnelite")

log_level = os.getenv("LOG_LEVEL", "INFO").upper()
log.setLevel(log_level)

logHandler = logging.StreamHandler()

formatter = jsonlogger.JsonFormatter(
    '%(asctime)s %(name)s %(levelname)s %(message)s'
)

logHandler.setFormatter(formatter)

if not log.handlers:
    log.addHandler(logHandler)
