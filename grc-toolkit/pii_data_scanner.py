"""
PII Data Scanner
-----------------
A lightweight compliance and data protection due diligence tool that scans a
directory of text-based files (.txt, .csv, .log, .md, .json) for patterns
commonly associated with Personally Identifiable Information (PII).

Use case: supporting data protection compliance reviews and due diligence
checks, e.g. before onboarding a new vendor's data export, or auditing an
internal shared drive for accidental exposure of sensitive data.

This is a detection aid, not a substitute for a full Data Protection Impact
Assessment (DPIA) or legal review. Always validate findings manually before
taking action.

Usage:
    python3 pii_data_scanner.py /path/to/directory
    python3 pii_data_scanner.py /path/to/directory -o custom_report.csv

Author: John Wambugu Ndung'u
"""

import os
import re
import csv
import argparse
from datetime import datetime


def _luhn_valid(number_str):
    """
    Validate a numeric string against the Luhn checksum algorithm, the
    same checksum used by Visa, Mastercard, and other major card networks
    to validate card numbers. Returns True only if the number passes the
    checksum, which sharply reduces false positives compared to matching
    on digit count alone.
    """
    digits = [int(d) for d in re.sub(r"\D", "", number_str)]
    if len(digits) < 13:
        return False
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Patterns are ordered from most specific/reliable to least specific. When
# two patterns could both match the same span of text, the higher-priority
# (earlier-listed) pattern wins and the lower-priority one is suppressed for
# that span. This avoids the same digit sequence being reported twice under
# different categories, e.g. an 8-digit ID also matching a loose phone
# pattern. Each pattern can optionally carry a validator function that must
# return True before a match is accepted.
PATTERNS = [
    ("Email Address", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), None),
    ("IBAN-style Bank Account", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"), None),
    ("Credit Card Number", re.compile(r"\b(?:\d[ -]?){13,16}\b"), _luhn_valid),
    ("Kenyan National ID (8 digits)", re.compile(r"\b\d{8}\b"), None),
    ("Phone Number (generic)", re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"), None),
]

SCANNABLE_EXTENSIONS = {".txt", ".csv", ".log", ".md", ".json"}


def scan_file(filepath):
    """
    Scan a single file for PII patterns. Returns a list of findings.
    Overlapping matches on the same line are resolved in favor of the
    higher-priority pattern to avoid duplicate or conflicting reports,
    and any pattern with a validator (e.g. Luhn check) must pass it
    before being counted.
    """
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                claimed_spans = []  # (start, end) spans already matched on this line
                for label, pattern, validator in PATTERNS:
                    for match in pattern.finditer(line):
                        start, end = match.span()
                        overlaps = any(
                            start < c_end and end > c_start
                            for c_start, c_end in claimed_spans
                        )
                        if overlaps:
                            continue
                        value = match.group()
                        if validator and not validator(value):
                            continue
                        claimed_spans.append((start, end))
                        findings.append({
                            "file": filepath,
                            "line": line_number,
                            "type": label,
                            "match_preview": _mask(value),
                        })
    except (UnicodeDecodeError, PermissionError, IsADirectoryError):
        pass  # Skip unreadable or binary files
    return findings


def _mask(value):
    """Mask a matched value for safe reporting — never log raw PII."""
    value = str(value)
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def scan_directory(root_dir):
    """Walk a directory tree and scan all supported file types."""
    all_findings = []
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext in SCANNABLE_EXTENSIONS:
                filepath = os.path.join(dirpath, filename)
                all_findings.extend(scan_file(filepath))
    return all_findings


def write_report(findings, output_path):
    """Write findings to a CSV compliance report."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "line", "type", "match_preview"])
        writer.writeheader()
        writer.writerows(findings)


def main():
    parser = argparse.ArgumentParser(
        description="Scan a directory for likely PII as part of a data protection compliance review."
    )
    parser.add_argument("directory", help="Path to the directory to scan")
    parser.add_argument(
        "-o", "--output",
        default=f"pii_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        help="Output CSV report filename"
    )
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"Error: '{args.directory}' is not a valid directory.")
        return

    print(f"Scanning '{args.directory}' for potential PII...")
    findings = scan_directory(args.directory)

    if findings:
        write_report(findings, args.output)
        print(f"\nScan complete. {len(findings)} potential PII instance(s) found.")
        print(f"Report written to: {args.output}")
        print("\nBreakdown by type:")
        summary = {}
        for item in findings:
            summary[item["type"]] = summary.get(item["type"], 0) + 1
        for label, count in summary.items():
            print(f"  - {label}: {count}")
    else:
        print("\nScan complete. No potential PII patterns detected.")

    print("\nNote: this tool flags patterns only. Every finding should be")
    print("manually verified before any compliance or remediation action is taken.")


if __name__ == "__main__":
    main()
