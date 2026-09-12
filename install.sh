#!/usr/bin/env bash
# AegisScan installer for Linux / macOS
set -euo pipefail

echo "🛡  AegisScan installer"
echo "----------------------"

if ! command -v python3 >/dev/null 2>&1; then
  echo "✖ Python 3.9+ is required. Install it first (e.g. apt install python3 / brew install python)."
  exit 1
fi

PYVER=$(python3 -c 'import sys; print("{}.{}".format(*sys.version_info[:2]))')
echo "✔ Python $PYVER found"

# optional: install as a CLI command (still zero dependencies)
if pip3 install . >/dev/null 2>&1; then
  echo "✔ installed as 'aegisscan' command"
  CMD="aegisscan"
else
  echo "• pip install skipped — you can still run: python3 -m aegisscan"
  CMD="python3 -m aegisscan"
fi

echo
echo "Quick start:"
echo "  $CMD demo                 # scan the bundled vulnerable demo app"
echo "  $CMD ui                   # professional web dashboard → http://127.0.0.1:8899"
echo "  $CMD scan --repo .        # scan a repository"
echo "  $CMD scan --url https://example.com"
echo "  $CMD scan --github owner/repo"
echo "  $CMD --help               # all Kali-style subcommands"
