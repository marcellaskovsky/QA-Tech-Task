# QA-Tech-Task
# Security Log Analyzer

A lightweight command line tool written in Python to parse and analyze system logs webserver.log and auth.log for potential security threats

## Features

- SQL Injection Detection
Detects malicious SQL queries in web requests while ignoring safe inputs like names with single quotes

- Directory Traversal Detection
Identifies unauthorized path traversal attempts using dot dot slash patterns

- Brute Force Tracking
Flags multiple failed login attempts from a single IP address within 60 seconds

- Modular Rule Engine
Detection rules are decoupled into an external configuration file

## How to Run

First setup the environment and install pytest

python -m venv venv
source venv/Scripts/activate
pip install pytest

Run the analyzer with the following command

python main.py

Run the automated tests with the following command

pytest -v

## Key Design Decisions

- Simplified Log Synchronization
Standard syslog files do not contain a year in their timestamps
To keep the parsing logic lightweight and clean we prepended a default year to match the webserver log timeframe

- Memory Friendly Parsing
Built using Python generators with yield to process logs line by line ensuring minimal RAM usage
