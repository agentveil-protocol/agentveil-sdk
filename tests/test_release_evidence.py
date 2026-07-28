from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _release_evidence_module():
    script = ROOT / "scripts" / "release_evidence.py"
    spec = importlib.util.spec_from_file_location("release_evidence", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_evidence_records_hashes_provenance_and_declared_dependencies(tmp_path):
    evidence = _release_evidence_module()
    artifact = tmp_path / "agentveil-mcp-proxy-0.7.36.tar.gz"
    artifact.write_bytes(b"release-artifact")
    output_dir = tmp_path / "evidence"

    paths = evidence.write_release_evidence(
        artifacts=[artifact],
        project_files=[ROOT / "packages" / "agentveil-mcp-proxy" / "pyproject.toml"],
        output_dir=output_dir,
        repository="https://github.com/agentveil-protocol/agentveil-sdk",
        commit="a" * 40,
        ref="refs/tags/v0.7.36-mcp-proxy",
        generated_at="2026-07-28T00:00:00Z",
    )

    checksums = paths["checksums"].read_text(encoding="utf-8")
    assert artifact.name in checksums
    assert len(checksums.split()[0]) == 64

    provenance = json.loads(paths["provenance"].read_text(encoding="utf-8"))
    assert provenance["source"]["commit"] == "a" * 40
    assert provenance["artifacts"][0]["name"] == artifact.as_posix()
    assert provenance["sbom"] == "declared-dependency-sbom.spdx.json"

    sbom = json.loads(paths["sbom"].read_text(encoding="utf-8"))
    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert "declared direct runtime dependencies" in sbom["comment"]
    assert any(package["name"] == "agentveil-mcp-proxy" for package in sbom["packages"])
    assert any(package["name"] == "agentveil" for package in sbom["packages"])
