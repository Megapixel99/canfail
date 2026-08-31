"""`canfail` — prove your guards can go red.

    canfail canfail.json
    canfail canfail.json --json

Exit codes: 0 every declared break was caught · 1 at least one guard is BLIND or failed
the wrong way · 2 the tool could not run.

A `look` never fails the run. A break this could not settle is a gap in the probe, not a
verdict about the guard, and it is counted and named rather than hidden.
"""

from __future__ import annotations

import argparse
import json
import sys

from .core import load_config, run_config


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="canfail",
        description="Break the thing on purpose and check that your check notices.")
    parser.add_argument("config", help="a canfail JSON file")
    parser.add_argument("--cwd", default=None, help="run the checks from here")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"canfail: {exc}\n")
        return 2

    report = run_config(config, cwd=args.cwd)

    if args.as_json:
        json.dump(report.to_dict(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 1 if report.findings else 0

    if report.findings:
        print(f"\nFINDINGS — {len(report.findings)}:")
        for o in report.findings:
            print(str(o))
    if report.looks:
        print(f"\nLOOK — {len(report.looks)}, which never fail the run:")
        for o in report.looks:
            print(str(o))
    if report.catches:
        print(f"\nCAUGHT — {len(report.catches)}:")
        for o in report.catches:
            print(str(o))

    # THE DENOMINATOR, ALWAYS. A config with no breaks and a config whose every break
    # was caught both print "no findings" otherwise, and they are not the same result.
    print(f"\n{len(report.outcomes)} declared break(s): {len(report.catches)} caught, "
          f"{len(report.findings)} not caught, {len(report.looks)} not settled")
    if not report.outcomes:
        print("  nothing was tried, so this is not a clean result — it is no result")
    return 1 if report.findings else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
