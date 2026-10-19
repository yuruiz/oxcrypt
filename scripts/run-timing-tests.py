#!/usr/bin/env python3
"""Run dudect executables directly; Cargo's --bench argument is not supported."""
import json
import pathlib
import subprocess
import sys


def main():
    artifacts = set()
    for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
        message = json.loads(line)
        if (message.get("reason") == "compiler-artifact"
                and message.get("target", {}).get("name") == "timing_leaks"
                and message.get("executable")):
            artifacts.add(message["executable"])
    if len(artifacts) != 1:
        raise SystemExit(f"Expected one timing benchmark executable, found {len(artifacts)}")
    executable = artifacts.pop()
    results = []
    for name in ("timing_hmac_verify", "timing_key_unwrap"):
        path = pathlib.Path(f"{name}.txt")
        with path.open("w") as output:
            subprocess.run([executable, "--filter", name], stdout=output,
                           stderr=subprocess.STDOUT, check=True, timeout=120)
        text = path.read_text()
        print(text, end="")
        results.append(text)
    pathlib.Path("timing_results.txt").write_text("\n".join(results))
    subprocess.run([sys.executable, "scripts/check-timing-results.py", "timing_results.txt"], check=True)


if __name__ == "__main__":
    main()
