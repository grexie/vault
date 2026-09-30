#!/usr/bin/env python3
"""Package the built extension for Chrome Web Store upload, without its dev key."""
import argparse
import json
from pathlib import Path
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path, help="Destination ZIP (run the extension build first)")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
files = ["manifest.json", "provider.js", "content.js", "worker.js", "popup.js",
         "popup.html", "popup.css", "icon-32.png", "icon-128.png"]
args.output.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(args.output, "w", zipfile.ZIP_DEFLATED) as archive:
    for name in files + ["LICENSE"]:
        data = (root / ("LICENSE" if name == "LICENSE" else "extension/dist/" + name)).read_bytes()
        if name == "manifest.json":
            manifest = json.loads(data)
            # Google signs Store packages. The source/dist key is only for giving
            # unpacked builds the same ID as that Store-signed installation.
            manifest.pop("key", None)
            data = (json.dumps(manifest, indent=2) + "\n").encode()
        info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, data)
print(args.output)
