#!/usr/bin/env python3
"""Fail closed when security-critical dudect measurements are absent or invalid."""
import math
import re
import sys
from pathlib import Path

REQUIRED = ("timing_hmac_verify", "timing_key_unwrap")

def check(text):
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    errors = []
    for name in REQUIRED:
        lines = [line for line in text.splitlines()
                 if re.search(rf"\bbench {name}\b", line)
                 and not re.fullmatch(rf"bench {name}\s+seeded with 0x[0-9a-fA-F]+", line.strip())]
        measurements = [re.search(r"max t\s*=\s*([^,\s]+)", line) for line in lines]
        if not measurements or any(match is None for match in measurements):
            errors.append(f"Missing or malformed result: {name}")
            continue
        for match in measurements:
            try:
                value = float(match.group(1))
            except ValueError:
                value = math.nan
            if not math.isfinite(value) or abs(value) > 4.5:
                errors.append(f"Invalid or failing timing result: {name}: {value}")
    return errors

if __name__ == "__main__":
    errors = check(Path(sys.argv[1]).read_text())
    for error in errors:
        print(error, file=sys.stderr)
    sys.exit(bool(errors))
