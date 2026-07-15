import re
import logging
from typing import Iterator, Optional, NamedTuple

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

WEBSERVER_LOG_PATTERN = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'      # IP address (4 dot-separated octets)
    r'-\s+-\s+'                                  # ident and authuser fields (always "-")
    r'\[(?P<timestamp>[^\]]+)\]\s+'              # timestamp inside square brackets
    r'"(?P<method>[A-Z]+)\s+(?P<path>.*?)\s+HTTP/\d\.\d"\s+'  # "METHOD path HTTP/x.x"
    r'(?P<status>\d{3})\s+'                      # 3-digit HTTP status code
    r'(?P<size>\d+|-)\s*$'                       # response size (digits or "-")
)


class WebLogEntry(NamedTuple):
    ip: str
    timestamp: str
    method: str
    path: str
    status: int
    size: int


def parse_webserver_line(line: str) -> Optional[WebLogEntry]:
    """Parse a single Common Log Format line into a WebLogEntry, or None if malformed."""
    line = line.strip()
    if not line:
        return None

    match = WEBSERVER_LOG_PATTERN.match(line)
    if not match:
        logger.warning("Skipping malformed webserver.log line: %r", line)
        return None

    data = match.groupdict()
    size = 0 if data["size"] == "-" else int(data["size"])

    return WebLogEntry(
        ip=data["ip"],
        timestamp=data["timestamp"],
        method=data["method"],
        path=data["path"],
        status=int(data["status"]),
        size=size,
    )


def read_webserver_log(file_path: str) -> Iterator[WebLogEntry]:
    """
    Generator that reads webserver.log line-by-line and yields parsed entries.
    Malformed lines are logged as warnings and skipped, not raised as exceptions.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as log_file:
            for line_number, raw_line in enumerate(log_file, start=1):
                entry = parse_webserver_line(raw_line)
                if entry is not None:
                    yield entry
                elif raw_line.strip():
                    logger.warning("Line %d could not be parsed and was skipped.", line_number)
    except FileNotFoundError:
        logger.error("Log file not found: %s", file_path)
    except OSError as e:
        logger.error("Error reading file %s: %s", file_path, e)
