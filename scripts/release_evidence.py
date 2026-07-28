#!/usr/bin/env python3
"""Write checksums, declared-dependency SBOM, and build provenance for releases."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]


SCHEMA_VERSION = "1.0"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _spdx_id(value: str, index: int) -> str:
    normalized = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-")
    return f"SPDXRef-{normalized or 'Dependency'}-{index}"


def _dependency_name(requirement: str) -> str:
    return re.split(r"[\s<>=!~;\[]", requirement, maxsplit=1)[0]


def _project_package(project_file: Path, index: int) -> tuple[dict[str, Any], list[dict[str, str]]]:
    with project_file.open("rb") as source:
        project = tomllib.load(source)["project"]

    package_id = _spdx_id(project["name"], index)
    package = {
        "SPDXID": package_id,
        "name": project["name"],
        "versionInfo": project["version"],
        "downloadLocation": project.get("urls", {}).get("Repository", "NOASSERTION"),
        "licenseConcluded": project.get("license", "NOASSERTION"),
        "licenseDeclared": project.get("license", "NOASSERTION"),
        "primaryPackagePurpose": "LIBRARY",
    }
    dependencies = [
        {"name": _dependency_name(requirement), "requirement": requirement}
        for requirement in project.get("dependencies", [])
    ]
    return package, dependencies


def write_release_evidence(
    *,
    artifacts: list[Path],
    project_files: list[Path],
    output_dir: Path,
    repository: str,
    commit: str,
    ref: str,
    generated_at: str | None = None,
) -> dict[str, Path]:
    """Write release evidence and return paths keyed by artifact type."""
    if not artifacts:
        raise ValueError("at least one --artifact is required")
    if not project_files:
        raise ValueError("at least one --project-file is required")

    artifact_records = []
    for artifact in artifacts:
        if not artifact.is_file():
            raise FileNotFoundError(f"artifact does not exist: {artifact}")
        artifact_records.append(
            {
                "name": artifact.as_posix(),
                "sha256": _sha256(artifact),
                "size_bytes": artifact.stat().st_size,
            }
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = generated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    checksums_path = output_dir / "SHA256SUMS"
    checksums_path.write_text(
        "".join(f"{record['sha256']}  {record['name']}\n" for record in artifact_records),
        encoding="utf-8",
    )

    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    for package_index, project_file in enumerate(project_files, start=1):
        package, dependencies = _project_package(project_file, package_index)
        packages.append(package)
        for dependency_index, dependency in enumerate(dependencies, start=1):
            dependency_id = _spdx_id(dependency["name"], package_index * 1000 + dependency_index)
            packages.append(
                {
                    "SPDXID": dependency_id,
                    "name": dependency["name"],
                    "downloadLocation": "NOASSERTION",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "comment": f"Declared dependency requirement: {dependency['requirement']}",
                }
            )
            relationships.append(
                {
                    "spdxElementId": package["SPDXID"],
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": dependency_id,
                }
            )

    sbom_path = output_dir / "declared-dependency-sbom.spdx.json"
    sbom_path.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": "agentveil-sdk-release-declared-dependencies",
                "documentNamespace": f"{repository}/provenance/{commit}",
                "creationInfo": {
                    "created": timestamp,
                    "creators": ["Tool: agentveil-sdk/scripts/release_evidence.py"],
                },
                "comment": "Release SBOM for declared direct runtime dependencies; it is not a resolved transitive dependency inventory.",
                "packages": packages,
                "relationships": relationships,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    provenance_path = output_dir / "build-provenance.json"
    provenance_path.write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "generated_at": timestamp,
                "source": {"repository": repository, "commit": commit, "ref": ref},
                "artifacts": artifact_records,
                "sbom": sbom_path.name,
                "checksums": checksums_path.name,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    return {"checksums": checksums_path, "sbom": sbom_path, "provenance": provenance_path}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", action="append", nargs="+", required=True, type=Path)
    parser.add_argument("--project-file", action="append", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--ref", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    write_release_evidence(
        artifacts=[artifact for group in args.artifact for artifact in group],
        project_files=args.project_file,
        output_dir=args.output_dir,
        repository=args.repository,
        commit=args.commit,
        ref=args.ref,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
