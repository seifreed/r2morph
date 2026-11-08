"""Fail when a critical smoke-test JUnit report contains skipped cases."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from defusedxml import ElementTree


def skipped_test_count(report_path: Path) -> int:
    return len(ElementTree.parse(report_path).getroot().findall(".//skipped"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="pytest JUnit XML report")
    skipped = skipped_test_count(parser.parse_args().report)
    if skipped:
        print(f"critical smoke report contains {skipped} skipped test(s)", file=sys.stderr)
        return 1
    print("critical smoke report contains no skipped tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
