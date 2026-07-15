import argparse
import json
import logging
from datetime import datetime
from typing import List

from parser import read_webserver_log, read_auth_log
from detector import (
    load_rules,
    SQLInjectionRule,
    DirectoryTraversalRule,
    BruteForceRule,
    Incident,
)

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
DEFAULT_LOG_YEAR = 2025  # auth.log has no year; force it to match webserver.log


def parse_web_timestamp(ts: str) -> datetime:
    """Parses Common Log Format timestamp, e.g. '03/Jul/2025:10:00:03 +0000'."""
    return datetime.strptime(ts.split(" ")[0], "%d/%b/%Y:%H:%M:%S")


def parse_auth_timestamp(ts: str, forced_year: int = DEFAULT_LOG_YEAR) -> datetime:
    """
    Parses syslog-style timestamp without a year, e.g. 'Jul  3 10:00:03',
    and forces a fixed year so it aligns with webserver.log timestamps.
    """
    parsed = datetime.strptime(ts, "%b %d %H:%M:%S")
    return parsed.replace(year=forced_year)


def build_rules(rules_config: dict) -> dict:
    """Instantiates all rule objects from the loaded JSON configuration."""
    return {
        "sql_injection": SQLInjectionRule(rules_config.get("sql_injection", {})),
        "directory_traversal": DirectoryTraversalRule(rules_config.get("directory_traversal", {})),
        "brute_force_web": BruteForceRule(
            rules_config.get("brute_force_web", {}), timestamp_parser=parse_web_timestamp
        ),
        "brute_force_ssh": BruteForceRule(
            rules_config.get("brute_force_ssh", {}), timestamp_parser=parse_auth_timestamp
        ),
    }


def scan_webserver_log(path: str, rules: dict) -> List[Incident]:
    incidents = []
    for entry in read_webserver_log(path):
        for rule_name in ("sql_injection", "directory_traversal", "brute_force_web"):
            incident = rules[rule_name].evaluate(entry)
            if incident:
                incidents.append(incident)
    return incidents


def scan_auth_log(path: str, rules: dict) -> List[Incident]:
    incidents = []
    for entry in read_auth_log(path):
        incident = rules["brute_force_ssh"].evaluate(entry)
        if incident:
            incidents.append(incident)
    return incidents


def print_report(incidents: List[Incident]) -> None:
    if not incidents:
        print("\nNo security incidents detected.\n")
        return

    print(f"\n{'=' * 60}")
    print(f"  SECURITY INCIDENT REPORT — {len(incidents)} finding(s)")
    print(f"{'=' * 60}\n")

    for i, incident in enumerate(incidents, start=1):
        print(f"[{i}] Severity: {incident.severity.upper()}")
        print(f"    Rule:        {incident.rule_name}")
        print(f"    IP:          {incident.ip or 'N/A'}")
        print(f"    Description: {incident.description}")
        print("-" * 60)


def export_incidents_json(incidents: List[Incident], output_path: str) -> None:
    try:
        serializable = [
            {
                "rule_name": inc.rule_name,
                "severity": inc.severity,
                "ip": inc.ip,
                "description": inc.description,
            }
            for inc in incidents
        ]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)
        print(f"\nIncidents exported to: {output_path}")
    except OSError as e:
        logger.error("Failed to write output file %s: %s", output_path, e)


def parse_args() -> argparse.Namespace:
    parser_cli = argparse.ArgumentParser(
        description="Security log analysis tool for webserver.log and auth.log."
    )
    parser_cli.add_argument(
        "--webserver-log", default="webserver.log", help="Path to the webserver log file."
    )
    parser_cli.add_argument(
        "--auth-log", default="auth.log", help="Path to the auth log file."
    )
    parser_cli.add_argument(
        "--rules", default="rules.json", help="Path to the detection rules JSON config."
    )
    parser_cli.add_argument(
        "--output", default=None, help="Optional path to export incidents as JSON."
    )
    return parser_cli.parse_args()


def main() -> None:
    args = parse_args()

    rules_config = load_rules(args.rules)
    if not rules_config:
        logger.error("No valid rules loaded. Exiting.")
        return

    rules = build_rules(rules_config)

    incidents = []
    incidents.extend(scan_webserver_log(args.webserver_log, rules))
    incidents.extend(scan_auth_log(args.auth_log, rules))

    incidents.sort(key=lambda inc: SEVERITY_ORDER.get(inc.severity, 99))

    print_report(incidents)

    if args.output:
        export_incidents_json(incidents, args.output)


if __name__ == "__main__":
    main()
