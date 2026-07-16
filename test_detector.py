import pytest
from detector import SQLInjectionRule
from typing import Iterator, Optional, NamedTuple
from parser import WebLogEntry

log = WebLogEntry(
    ip="192.168.1.1", 
    timestamp="16/Jul/2025:12:00:00 +0000", 
    method="GET", 
    path="/index.html", 
    status=200, 
    size=1024
)

def test_sql_injection_detected():
    config = {
        "enabled": True,
        "signatures": ["union", "select"]
    }


    rule = SQLInjectionRule(config)

    bad_entry = WebLogEntry(
        ip="10.0.0.88",
        timestamp="03/Jul/2025:10:00:00 +0000",
        method="GET",
        path="/search?q=' UNION SELECT * FROM users--",
        status=200,
        size=100
    )

    incident = rule.evaluate(bad_entry)

    assert incident is not None
    assert incident.rule_name == "sql_injection"
    assert incident.severity == "high"


def test_sql_injection_ignored_safe_query():
    config = {
        "enabled": True,
        "signatures": ["union", "select"]
    }
        
    rule = SQLInjectionRule(config)

    safe_entry = WebLogEntry(
        ip="192.168.10.15",
        timestamp="05/Jul/2025:15:30:00 +0000",
        method="GET",
        path="/search?q= O'Brien",
        status=200,
        size=100
    )

    incident = rule.evaluate(safe_entry)

    assert incident is None

