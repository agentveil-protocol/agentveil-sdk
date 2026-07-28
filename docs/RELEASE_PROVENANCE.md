# Release provenance and signing

This document covers releases from `agentveil-protocol/agentveil-sdk`, including
the separately licensed `agentveil-mcp-proxy` package. It adds evidence to a
release; it does not change the MIT/BUSL package boundary.

## Ownership and license boundary

- Copyright holder: **Oleg Boiko**.
- The public SDK surfaces remain MIT licensed.
- `packages/agentveil-mcp-proxy/` remains BUSL-1.1. Its source files carry
  SPDX copyright and license headers, and its distributions contain `LICENSE`
  and `NOTICE`.

## Required release preflight

Run the applicable test suite and inspect the proposed release commit before
creating a tag. Do not create, move, or retag an existing release tag to recover
from a failed workflow.

Create an annotated, signed tag for the exact reviewed commit:

```bash
git tag -s vX.Y.Z-mcp-proxy -m "Release agentveil-mcp-proxy X.Y.Z"
scripts/verify_release_tag.sh vX.Y.Z-mcp-proxy
```

`verify_release_tag.sh` runs `git verify-tag`; it must succeed in the release
operator's local signing environment before a tag is pushed. The operator must
maintain the corresponding public signing key and verification configuration.

## Build evidence produced by the publish workflow

After distributions pass `twine check`, the release workflow creates:

- `SHA256SUMS` for the SDK and MCP Proxy wheel/sdist files;
- `declared-dependency-sbom.spdx.json`, an SPDX 2.3 SBOM of declared direct runtime dependencies only;
- `build-provenance.json` with source repository, commit, ref, artifact hashes,
  and the evidence file names;
- a GitHub artifact attestation signed through GitHub Actions/Sigstore.

The SBOM is intentionally labelled as declared-dependency data. It must not be
represented as a resolved transitive dependency inventory.

Download the workflow evidence artifact and verify a published distribution
against its checksum before relying on it. Verify the GitHub attestation with
the GitHub CLI and the public repository identity:

```bash
gh attestation verify <artifact-file> --repo agentveil-protocol/agentveil-sdk
```

## Preserve evidence for an investigation

For a suspected copied or non-compliant distribution, preserve the original
URL, repository commit or package version, release evidence, checksum result,
and a focused source diff. Do not alter the target repository or send a legal
notice before reviewing the evidence and obtaining legal advice.
