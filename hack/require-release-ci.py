#!/usr/bin/env python3
"""Require a completed, successful main CI run for the exact release commit."""

import argparse
import json
import pathlib
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("revision")
parser.add_argument("--github-output")
args = parser.parse_args()
runs = json.load(sys.stdin).get("workflow_runs", [])
qualified = [run for run in runs if (
    run.get("head_sha") == args.revision
    and run.get("head_branch") == "main"
    and run.get("event") in {"push", "workflow_dispatch"}
    and run.get("status") == "completed"
    and run.get("conclusion") == "success"
)]
if not qualified:
    raise SystemExit("Release blocked: no successful main CI run for this exact commit")
print(f"Verified successful main CI for {args.revision}")
if args.github_output:
    run_id = int(max(qualified, key=lambda run: int(run["id"]))["id"])
    if run_id <= 0:
        raise SystemExit("Invalid workflow run identity")
    with pathlib.Path(args.github_output).open("a") as output:
        output.write(f"run_id={run_id}\n")
