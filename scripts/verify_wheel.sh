#!/usr/bin/env bash
# Build a wheel + sdist, install the wheel into a scratch venv with the [mcp]
# extra, and run packaging smoke checks. Use this before tagging a release.
#
# Usage: scripts/verify_wheel.sh
#
# Requires: python3.10+, pip. Will create a scratch venv under /tmp and
# remove it on exit.
#
# This script does NOT publish to PyPI. It does NOT run network-dependent
# MCP server checks beyond `agentveil-mcp --help` (argparse-only).
# For MCP Proxy behavior releases, run scripts/mcp_proxy_release_acceptance.py
# against the release candidate wheel after this packaging smoke passes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PYTHON="${PYTHON:-python3}"
BUILD_VENV="$(mktemp -d)/build_venv"
INSTALL_VENV="$(mktemp -d)/install_venv"

cleanup() {
    rm -rf "$BUILD_VENV" "$INSTALL_VENV"
}
trap cleanup EXIT

echo "==> Creating scratch build venv: $BUILD_VENV"
"$PYTHON" -m venv "$BUILD_VENV"
# shellcheck disable=SC1091
source "$BUILD_VENV/bin/activate"
python -m pip install --quiet --upgrade pip build

echo "==> Cleaning previous dist/ and egg-info"
rm -rf dist/ build/ agentveil.egg-info/ *.egg-info

echo "==> python -m build"
python -m build

WHEEL="$(ls dist/agentveil-*-py3-none-any.whl | head -n 1)"
SDIST="$(ls dist/agentveil-*.tar.gz | head -n 1)"
echo "==> Built artefacts:"
echo "    wheel: $WHEEL"
echo "    sdist: $SDIST"

echo "==> Wheel contents:"
python -c "import zipfile, sys; [print('    ' + n) for n in sorted(zipfile.ZipFile(sys.argv[1]).namelist())]" "$WHEEL"

echo "==> Wheel entry_points.txt:"
python -c "
import zipfile, sys
z = zipfile.ZipFile(sys.argv[1])
matches = [name for name in z.namelist() if name.endswith('/entry_points.txt')]
if not matches:
    raise FileNotFoundError('entry_points.txt not found')
print(z.read(matches[0]).decode())
" "$WHEEL" \
    || echo "    (entry_points.txt not found)"

echo "==> Wheel METADATA (extras):"
python -c "
import zipfile, sys, re
z = zipfile.ZipFile(sys.argv[1])
for name in z.namelist():
    if name.endswith('/METADATA'):
        text = z.read(name).decode()
        for line in text.splitlines():
            if re.match(r'^(Name|Version|Provides-Extra|Requires-Dist):', line):
                print('    ' + line)
        break
" "$WHEEL"

deactivate

echo "==> Creating scratch install venv: $INSTALL_VENV"
"$PYTHON" -m venv "$INSTALL_VENV"
# shellcheck disable=SC1091
source "$INSTALL_VENV/bin/activate"
python -m pip install --quiet --upgrade pip

echo "==> pip install wheel with [mcp] extra"
python -m pip install "${WHEEL}[mcp]"

echo "==> which agentveil-mcp"
which agentveil-mcp

echo "==> agentveil-mcp --help (argparse only, no network)"
agentveil-mcp --help

echo "==> Canonical import smoke"
python -c "
import agentveil_mcp.server as s
from mcp.server.fastmcp import FastMCP
assert callable(s.main), 'main not callable'
assert isinstance(s.mcp, FastMCP), 'mcp not a FastMCP instance'
print('    canonical: OK')
"

echo "==> Shim DeprecationWarning + identity"
python -c "
import warnings
with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter('always')
    import mcp_server.server
dep = [w for w in caught if issubclass(w.category, DeprecationWarning)]
assert dep, 'expected DeprecationWarning on import mcp_server.server'
print('    DeprecationWarnings fired:', len(dep))

warnings.simplefilter('ignore', DeprecationWarning)
from mcp_server.server import main as shim_main
from agentveil_mcp.server import main as canonical_main
assert shim_main is canonical_main, 'shim main is not canonical main'
print('    shim -> canonical identity: OK')
"

deactivate

echo
echo "==> All packaging smoke checks passed."
echo "==> Artefacts left in: $REPO_ROOT/dist/"
