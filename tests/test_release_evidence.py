from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
RELEASE_PROVENANCE = ROOT / "docs" / "RELEASE_PROVENANCE.md"
VERIFY_RELEASE_TAG = ROOT / "scripts" / "verify_release_tag.sh"


def _release_evidence_module():
    script = ROOT / "scripts" / "release_evidence.py"
    spec = importlib.util.spec_from_file_location("release_evidence", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _distribution_license_module():
    script = ROOT / "scripts" / "verify_proxy_distribution_licenses.py"
    spec = importlib.util.spec_from_file_location("verify_proxy_distribution_licenses", script)
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


def test_release_provenance_document_and_tag_preflight_are_present():
    document = RELEASE_PROVENANCE.read_text(encoding="utf-8")
    verifier = VERIFY_RELEASE_TAG.read_text(encoding="utf-8")

    assert "Copyright holder: **Oleg Boiko**" in document
    assert "git tag -s" in document
    assert "gh attestation verify" in document
    assert "declared direct runtime dependencies only" in document
    assert 'git verify-tag "$tag_name"' in verifier


def test_distribution_license_verifier_accepts_proxy_wheel_and_sdist(tmp_path):
    verifier = _distribution_license_module()
    wheel = tmp_path / "agentveil_mcp_proxy-0.7.36-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("agentveil_mcp_proxy-0.7.36.dist-info/licenses/LICENSE", "BUSL")
        archive.writestr("agentveil_mcp_proxy-0.7.36.dist-info/licenses/NOTICE", "notice")
        archive.writestr(
            "agentveil_mcp_proxy-0.7.36.dist-info/METADATA",
            "License-Expression: BUSL-1.1\nLicense-File: LICENSE\nLicense-File: NOTICE\n",
        )

    sdist = tmp_path / "agentveil_mcp_proxy-0.7.36.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for name in ("LICENSE", "NOTICE"):
            payload = b"license material"
            member = tarfile.TarInfo(f"agentveil_mcp_proxy-0.7.36/{name}")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))

    verifier.verify_distribution_licenses([wheel, sdist])
