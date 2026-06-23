"""Write a minimal offline wheel for the product route package fixture."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

PRODUCT_ROUTE_TEST_PACKAGE_NAME = "agentveil-route-test-pkg"
PRODUCT_ROUTE_TEST_PACKAGE_VERSION = "0.1.0"
PRODUCT_ROUTE_TEST_WHEEL_NAME = (
    f"agentveil_route_test_pkg-{PRODUCT_ROUTE_TEST_PACKAGE_VERSION}-py3-none-any.whl"
)

_INIT_PY = (
    "def mark_postinstall(project_root: str) -> None:\n"
    "    from pathlib import Path\n"
    "    Path(project_root, '.postinstall-ran').write_text('1', encoding='utf-8')\n"
)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_offline_product_route_test_wheel(dist_dir: Path) -> Path:
    """Materialize a deterministic pure-Python wheel without PyPI or build tooling."""

    dist_dir.mkdir(parents=True, exist_ok=True)
    wheel_path = dist_dir / PRODUCT_ROUTE_TEST_WHEEL_NAME
    dist_info = f"agentveil_route_test_pkg-{PRODUCT_ROUTE_TEST_PACKAGE_VERSION}.dist-info"
    metadata = (
        "Metadata-Version: 2.1\n"
        f"Name: {PRODUCT_ROUTE_TEST_PACKAGE_NAME}\n"
        f"Version: {PRODUCT_ROUTE_TEST_PACKAGE_VERSION}\n"
    ).encode("utf-8")
    wheel_meta = (
        "Wheel-Version: 1.0\n"
        "Generator: agentveil-product-route-fixture\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    ).encode("utf-8")
    entry_points = (
        "[console_scripts]\n"
        "postinstall = agentveil_route_pkg:mark_postinstall\n"
    ).encode("utf-8")
    payload_files = {
        "agentveil_route_pkg/__init__.py": _INIT_PY.encode("utf-8"),
        f"{dist_info}/METADATA": metadata,
        f"{dist_info}/WHEEL": wheel_meta,
        f"{dist_info}/entry_points.txt": entry_points,
    }
    record_lines: list[str] = []
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative_path, body in sorted(payload_files.items()):
            archive.writestr(relative_path, body)
            record_lines.append(
                f"{relative_path},sha256={_sha256_hex(body)},{len(body)}",
            )
        record_body = "\n".join(record_lines) + f"\n{dist_info}/RECORD,,\n"
        archive.writestr(f"{dist_info}/RECORD", record_body.encode("utf-8"))
    return wheel_path


__all__ = [
    "PRODUCT_ROUTE_TEST_PACKAGE_NAME",
    "PRODUCT_ROUTE_TEST_PACKAGE_VERSION",
    "PRODUCT_ROUTE_TEST_WHEEL_NAME",
    "write_offline_product_route_test_wheel",
]
