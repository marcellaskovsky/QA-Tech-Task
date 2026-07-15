import re
import json
import logging
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional, Dict, Any, Union, List, NamedTuple

logger = logging.getLogger(__name__)


class Incident(NamedTuple):
    rule_name: str
    severity: str
    ip: Optional[str]
    description: str
    raw_entry: Any


def load_rules(config_path: str) -> Dict[str, Any]:
    """Load rule thresholds and signatures from an external JSON file."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error("Failed to load rules config %s: %s", config_path, e)
        return {}


class BaseRule(ABC):
    """Every detection rule implements evaluate() and returns an Incident or None."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", False)

    @abstractmethod
    def evaluate(self, entry: Any) -> Optional[Incident]:
        ...


class SQLInjectionRule(BaseRule):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.patterns = [
            re.compile(sig, re.IGNORECASE) for sig in self.config.get("signatures", [])
        ]

    def evaluate(self, entry) -> Optional[Incident]:
        if not self.enabled or not hasattr(entry, "path"):
            return None
        for pattern in self.patterns:
            if pattern.search(entry.path):
                return Incident(
                    rule_name="sql_injection",
                    severity="high",
                    ip=entry.ip,
                    description=f"SQL injection pattern matched in path: {entry.path}",
                    raw_entry=entry,
                )
        return None


class DirectoryTraversalRule(BaseRule):
    def evaluate(self, entry) -> Optional[Incident]:
        if not self.enabled or not hasattr(entry, "path"):
            return None
        for signature in self.config.get("signatures", []):
            if signature in entry.path:
                return Incident(
                    rule_name="directory_traversal",
                    severity="high",
                    ip=entry.ip,
                    description=f"Directory traversal pattern '{signature}' found in path: {entry.path}",
                    raw_entry=entry,
                )
        return None


class BruteForceTracker:
    """Encapsulates sliding-window state for repeated-failure detection, keyed by IP."""

    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: Dict[str, deque] = defaultdict(deque)

    def record_and_check(self, key: str, timestamp: datetime) -> bool:
        history = self._attempts[key]
        history.append(timestamp)
        while history and (timestamp - history[0]).total_seconds() > self.window_seconds:
            history.popleft()
        return len(history) >= self.max_attempts


class BruteForceRule(BaseRule):
    """Handles both web (401/403) and ssh (failed_password) brute-force detection."""

    def __init__(self, config: Dict[str, Any], timestamp_parser):
        super().__init__(config)
        self.tracker = BruteForceTracker(
            max_attempts=config.get("max_failed_logins", 3),
            window_seconds=config.get("time_window_seconds", 60),
        )
        self.parse_timestamp = timestamp_parser
        self.target_status_codes = config.get("target_status_codes")

    def evaluate(self, entry) -> Optional[Incident]:
        if not self.enabled:
            return None

        is_failure = (
            (self.target_status_codes and getattr(entry, "status", None) in self.target_status_codes)
            or (getattr(entry, "action", None) == "failed_password")
        )
        if not is_failure:
            return None

        ip = entry.ip
        if not ip:
            return None

        timestamp = self.parse_timestamp(entry.timestamp)
        if self.tracker.record_and_check(ip, timestamp):
            return Incident(
                rule_name="brute_force",
                severity="critical",
                ip=ip,
                description=f"{self.tracker.max_attempts}+ failed attempts from {ip} within {self.tracker.window_seconds}s",
                raw_entry=entry,
            )
        return None
    