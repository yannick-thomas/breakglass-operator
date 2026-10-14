#!/usr/bin/env python3
"""Stage a chart with the same immutable manager image as the installer bundle."""

import argparse
import pathlib
import re
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--image", required=True)
parser.add_argument("--version", required=True)
parser.add_argument("--app-version", required=True)
parser.add_argument("--helm", default="helm")
parser.add_argument("--destination", default="dist")
args = parser.parse_args()
if not re.fullmatch(r"[a-z0-9][a-z0-9.:/_-]*[a-z0-9]@sha256:[a-f0-9]{64}", args.image):
    parser.error("--image must be a repository@sha256:<64 hex digits> from gated CI")

repo = pathlib.Path(__file__).resolve().parent.parent
destination = pathlib.Path(args.destination).resolve()
destination.mkdir(parents=True, exist_ok=True)
repository, digest = args.image.split("@")
with tempfile.TemporaryDirectory(prefix="breakglass-chart-") as directory:
    chart = pathlib.Path(directory) / "breakglass-operator"
    shutil.copytree(repo / "charts/breakglass-operator", chart)
    values_path = chart / "values.yaml"
    values = values_path.read_text()
    # Only the operator image block is changed. The guard uses the same image;
    # the optional WebUI keeps its separate, explicitly supplied image.
    values = re.sub(r"(?m)^  repository: .*$", f"  repository: {repository}", values, count=1)
    values = re.sub(r'(?m)^  digest: .*$', f'  digest: "{digest}"', values, count=1)
    values_path.write_text(values)
    subprocess.run([args.helm, "lint", str(chart), "--strict"], check=True)
    subprocess.run([
        args.helm, "package", str(chart), "--version", args.version,
        "--app-version", args.app_version, "--destination", str(destination),
    ], check=True)
