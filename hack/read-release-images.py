#!/usr/bin/env python3
"""Read immutable images from an artifact of the successful CI run, not SHA tags."""

import argparse
import json
import pathlib
import re

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("manifest")
parser.add_argument("revision")
parser.add_argument("--operator-repository", required=True)
parser.add_argument("--webui-repository", required=True)
parser.add_argument("--github-output", required=True)
args = parser.parse_args()
manifest = json.loads(pathlib.Path(args.manifest).read_text())
if manifest.get("schemaVersion") != 1 or manifest.get("sourceRevision") != args.revision:
    raise SystemExit("Release bundle does not belong to this exact source revision")
images = manifest.get("images", {})
resolved = {}
for component, repository in [("operator", args.operator_repository), ("webui", args.webui_repository)]:
    image = images.get(component, "")
    if not re.fullmatch(re.escape(repository) + r"@sha256:[a-f0-9]{64}", image):
        raise SystemExit(f"Invalid digest-pinned {component} image in the gated release bundle")
    resolved[component] = image.split("@", 1)[1]
with pathlib.Path(args.github_output).open("a") as output:
    for component, digest in resolved.items():
        output.write(f"{component}_digest={digest}\n")
