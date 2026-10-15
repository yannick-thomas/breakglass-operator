#!/usr/bin/env python3
"""Package the chart and record both images from the same gated source revision."""

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--image", required=True)
parser.add_argument("--webui-image", required=True)
parser.add_argument("--source-revision")
parser.add_argument("--version", required=True)
parser.add_argument("--app-version", required=True)
parser.add_argument("--helm", default="helm")
parser.add_argument("--destination", default="dist")
args = parser.parse_args()
for flag, image in [("--image", args.image), ("--webui-image", args.webui_image)]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9.:/_-]*[a-z0-9]@sha256:[a-f0-9]{64}", image):
        parser.error(f"{flag} must be a repository@sha256:<64 hex digits> from gated CI")
if args.source_revision and not re.fullmatch(r"[a-f0-9]{40}", args.source_revision):
    parser.error("--source-revision must be the full Git commit SHA")

repo = pathlib.Path(__file__).resolve().parent.parent
destination = pathlib.Path(args.destination).resolve()
destination.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="breakglass-chart-") as directory:
    chart = pathlib.Path(directory) / "breakglass-operator"
    shutil.copytree(repo / "charts/breakglass-operator", chart)
    values_path = chart / "values.yaml"
    values = values_path.read_text()
    # Indentation distinguishes the two explicit image blocks. Refuse a changed
    # shape rather than silently shipping an unpinned image after a refactor.
    for image, indent in [(args.image, "  "), (args.webui_image, "    ")]:
        repository, digest = image.split("@")
        for key, value in [("repository", repository), ("digest", digest), ("tag", "")]:
            values, count = re.subn(
                rf"(?m)^{indent}{key}: .*$", f'{indent}{key}: "{value}"', values,
            )
            if count != 1:
                raise SystemExit(f"expected exactly one {indent!r}{key} value, found {count}")
    values_path.write_text(values)
    subprocess.run([args.helm, "lint", str(chart), "--strict"], check=True)
    subprocess.run([
        args.helm, "package", str(chart), "--version", args.version,
        "--app-version", args.app_version, "--destination", str(destination),
    ], check=True)
    metadata = {
        "schemaVersion": 1,
        "sourceRevision": args.source_revision,
        "chart": {"name": "breakglass-operator", "version": args.version, "appVersion": args.app_version},
        "images": {"operator": args.image, "webui": args.webui_image},
    }
    (destination / "release.json").write_text(json.dumps(metadata, indent=2) + "\n")
