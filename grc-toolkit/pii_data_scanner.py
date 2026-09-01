"""
PII Data Scanner
-----------------
A lightweight compliance and data protection due diligence tool that scans a
directory of text-based files (.txt, .csv, .log, .md) for patterns commonly
associated with Personally Identifiable Information (PII).

Use case: supporting data protection compliance reviews and due diligence
checks, e.g. before onboarding a new vendor's data export, or auditing an
internal shared drive for accidental exposure of sensitive data.

This is a detection aid, not a substitute for a full Data Protection Impact
Assessment (DPIA) or legal review. Always validate findings manually before
taking action.

Author: John Wambugu Ndung'u
"""

import os
import re
import csv
import argparse
from datetime import datetime

# --- Pattern definitions -----------------------------------------------------
# These are intentionally broad, general-purpose patterns. Real deployments
# should tune these to the specific ID formats and data types relevant to
# the organization's operating jurisdictions.

PATTERNS = {
    "Email Address": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "Phone Number (generic)": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"),
    "Kenyan National ID (8 digits)": re.compile(r"\b\d{8}\b"),
    "Credit Card Number (13-16 digits, optionally spaced/dashed)": re.compile(
        r"\b(?:\d[ -]*?){13,16}\b"
    ),
    "IBAN-style Bank Account": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
}

SCANNABLE_EXTENSIONS = {".txt", ".csv", ".log", ".md", ".json"}


def scan_file(filepath):
    """Scan a single file for PII patterns. Returns a list of findings."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                for label, pattern in PATTERNS.items():
                    matches = pattern.findall(line)
                    for match in matches:
                        findings.append({
                            "file": filepath,
                            "line": line_number,
                            "type": label,
                            "match_preview": _mask(match),
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
