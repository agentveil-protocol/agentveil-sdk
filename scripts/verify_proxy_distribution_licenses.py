#!/usr/bin/env python3
"""Verify that MCP Proxy release artifacts retain BUSL license material."""

from __future__ import annotations

import argparse
from pathlib import Path
import tarfile
import zipfile


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_distribution_licenses(artifacts: list[Path]) -> None:
    """Fail unless every Proxy wheel/sdist contains the required license evidence."""
    _require(bool(artifacts), "at least one distribution artifact is required")
    for artifact in artifacts:
        _require(artifact.is_file(), f"artifact does not exist: {artifact}")
        if artifact.suffix == ".whl":
            with zipfile.ZipFile(artifact) as archive:
                names = archive.namelist()
                _require(any(name.endswith(".dist-info/licenses/LICENSE") for name in names), f"wheel is missing LICENSE: {artifact}")
                _require(any(name.endswith(".dist-info/licenses/NOTICE") for name in names), f"wheel is missing NOTICE: {artifact}")
                metadata_name = next((name for name in names if name.endswith(".dist-info/METADATA")), None)
                _require(metadata_name is not None, f"wheel is missing METADATA: {artifact}")
                metadata = archive.read(metadata_name).decode("utf-8")
                _require("License-Expression: BUSL-1.1" in metadata, f"wheel has no BUSL expression: {artifact}")
                _require("License-File: LICENSE" in metadata, f"wheel does not declare LICENSE: {artifact}")
                _require("License-File: NOTICE" in metadata, f"wheel does not declare NOTICE: {artifact}")
        elif artifact.name.endswith(".tar.gz"):
            with tarfile.open(artifact, "r:gz") as archive:
                names = archive.getnames()
                _require(any(name.endswith("/LICENSE") for name in names), f"sdist is missing LICENSE: {artifact}")
                _require(any(name.endswith("/NOTICE") for name in names), f"sdist is missing NOTICE: {artifact}")
        else:
            raise ValueError(f"unsupported distribution artifact: {artifact}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args()
    verify_distribution_licenses(args.artifacts)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
