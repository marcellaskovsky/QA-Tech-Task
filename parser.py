import re
import logging
from typing import Iterator, Optional, NamedTuple

# Konfiguracja logowania (wypisywanie ostrzeżeń)
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# =====================================================================
# CZĘŚĆ 1: PARSER WEBSERVER.LOG
# =====================================================================

WEBSERVER_LOG_PATTERN = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'                    # Adres IP
    r'-\s+-\s+'                                                # Pomijane znaki "- -"
    r'\[(?P<timestamp>[^\]]+)\]\s+'                            # Timestamp w nawiasach kwadratowych
    r'"(?P<method>[A-Z]+)\s+(?P<path>.*?)\s+HTTP/\d\.\d"\s+'   # Metoda i ścieżka HTTP
    r'(?P<status>\d{3})\s+'                                    # Kod statusu (np. 200, 404)
    r'(?P<size>\d+|-)\s*$'                                     # Rozmiar odpowiedzi (lub "-")
)

class WebLogEntry(NamedTuple):
    ip: str
    timestamp: str
    method: str
    path: str
    status: int
    size: int

def parse_webserver_line(line: str) -> Optional[WebLogEntry]:
    """Parsuje pojedynczą linijkę z webserver.log."""
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
    """Generator czytający plik webserver.log linia po linii."""
    try:
        with open(file_path, "r", encoding="utf-8") as log_file:
            for line_number, raw_line in enumerate(log_file, start=1):
                entry = parse_webserver_line(raw_line)
                if entry is not None:
                    yield entry
    except FileNotFoundError:
        logger.error("Log file not found: %s", file_path)
    except OSError as e:
        logger.error("Error reading file %s: %s", file_path, e)


# =====================================================================
# CZĘŚĆ 2: PARSER AUTH.LOG
# =====================================================================

AUTH_LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # Data np. "Jul  3 10:00:03"
    r'\S+\s+'                                                  # Nazwa hosta (np. "server") - pomijamy
    r'(?P<process>sshd|sudo)(?:\[\d+\])?:\s+'                  # Proces: sshd lub sudo + opcjonalny PID
    r'(?P<message>.+)$'                                        # Reszta wiadomości
)

SSHD_MESSAGE_PATTERN = re.compile(
    r'^(?:Failed password for (?:invalid user )?(?P<fail_user>\S+)|'
    r'Accepted (?:password|publickey) for (?P<ok_user>\S+)|'
    r'Connection closed by (?P<conn_ip>\d{1,3}(?:\.\d{1,3}){3}))'
    r'(?:\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}))?'
)

SUDO_MESSAGE_PATTERN = re.compile(
    r'^(?P<user>\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.+)$'
)

class AuthLogEntry(NamedTuple):
    timestamp: str
    process: str
    user: Optional[str]
    ip: Optional[str]
    action: str

def parse_auth_line(line: str) -> Optional[AuthLogEntry]:
    """Parsuje pojedynczą linijkę z auth.log."""
    line = line.strip()
    if not line:
        return None

    outer_match = AUTH_LOG_PATTERN.match(line)
    if not outer_match:
        logger.warning("Skipping malformed auth.log line: %r", line)
        return None

    timestamp = outer_match.group("timestamp")
    process = outer_match.group("process")
    message = outer_match.group("message")

    if process == "sshd":
        sshd_match = SSHD_MESSAGE_PATTERN.match(message)
        if not sshd_match:
            logger.warning("Unrecognized sshd message, skipping: %r", line)
            return None

        data = sshd_match.groupdict()
        user = data["fail_user"] or data["ok_user"]
        ip = data["ip"] or data["conn_ip"]

        if data["fail_user"]:
            action = "failed_password"
        elif data["ok_user"]:
            action = "accepted_login"
        else:
            action = "connection_closed"

        return AuthLogEntry(timestamp=timestamp, process="sshd", user=user, ip=ip, action=action)

    else:  # process == "sudo"
        sudo_match = SUDO_MESSAGE_PATTERN.match(message)
        if not sudo_match:
            logger.warning("Unrecognized sudo message, skipping: %r", line)
            return None

        data = sudo_match.groupdict()
        return AuthLogEntry(
            timestamp=timestamp,
            process="sudo",
            user=data["user"],
            ip=None,
            action=f'COMMAND={data["command"]} (as {data["target_user"]})',
        )

def read_auth_log(file_path: str) -> Iterator[AuthLogEntry]:
    """Generator czytający plik auth.log linia po linii."""
    try:
        with open(file_path, "r", encoding="utf-8") as log_file:
            for line_number, raw_line in enumerate(log_file, start=1):
                entry = parse_auth_line(raw_line)
                if entry is not None:
                    yield entry
    except FileNotFoundError:
        logger.error("Log file not found: %s", file_path)
    except OSError as e:
        logger.error("Error reading file %s: %s", file_path, e)

