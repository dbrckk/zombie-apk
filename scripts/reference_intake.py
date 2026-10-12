#!/usr/bin/env python3
"""Catalog locally acquired Android references without publishing APK binaries."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

CHANNELS = ("publisher_direct", "publisher_release", "fdroid", "device_export", "store_only", "third_party_unverified")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
PACKAGE = re.compile(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+\Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_archive(apk: Path) -> tuple[int, str]:
    if not apk.is_file() or apk.suffix.lower() != ".apk":
        raise ValueError("Provide an existing .apk file (not a store URL or XAPK)")
    size = apk.stat().st_size
    if not 100 <= size <= 3 * 1024**3:
        raise ValueError("APK size outside safe limits")
    try:
        with zipfile.ZipFile(apk) as archive:
            infos = archive.infolist()
            if not 0 < len(infos) <= 50000:
                raise ValueError("APK archive has an unsafe number of entries")
            if sum(max(0, entry.file_size) for entry in infos) > 8 * 1024**3:
                raise ValueError("APK archive exceeds expanded-size budget")
            if not any(x.filename == "AndroidManifest.xml" for x in infos):
                raise ValueError("APK must contain AndroidManifest.xml")
            if any(".." in x.filename.split("/") or x.filename.startswith("/") for x in infos):
                raise ValueError("APK archive contains unsafe paths")
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ValueError("File is not a valid APK ZIP archive") from exc
    return size, sha256_file(apk)


def read_package(apk: Path) -> str | None:
    if shutil.which("aapt") is None:
        return None
    result = subprocess.run(["aapt", "dump", "badging", str(apk)], capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        return None
    match = re.search(r"^package: name='([^']+)'", result.stdout, re.MULTILINE)
    return match.group(1) if match else None


def read_signer(apk: Path) -> str | None:
    if shutil.which("apksigner") is None:
        return None
    result = subprocess.run(["apksigner", "verify", "--print-certs", str(apk)], capture_output=True, text=True, timeout=60, check=False)
    if result.returncode != 0:
        raise ValueError("APK signing verification failed")
    match = re.search(r"Signer #1 certificate SHA-256 digest:\s*([0-9a-fA-F]{64})", result.stdout)
    return match.group(1).lower() if match else None


def run_rea(apk: Path, evidence_path: Path) -> None:
    rea = shutil.which("rea")
    if not rea:
        raise RuntimeError("REA CLI unavailable; install rea-agents and Android/JADX prerequisites first")
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = evidence_path.with_suffix(".partial")
    try:
        with temporary.open("wb") as output:
            result = subprocess.run([rea, "inspect-android-package", str(apk), "--json"], stdout=output, stderr=subprocess.PIPE, timeout=300, check=False)
        if result.returncode:
            raise RuntimeError("REA Android inspection failed; check REA/JDK/JADX setup")
        with temporary.open(encoding="utf-8") as stream:
            if not isinstance(json.load(stream), dict):
                raise RuntimeError("REA output was not a JSON object")
        temporary.replace(evidence_path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--slug", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--publisher", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--listing-url", required=True, help="Publisher or store listing; NOT an APK download URL")
    parser.add_argument("--download-url", default=None, help="Actual direct APK URL, when present")
    parser.add_argument("--source-type", required=True, choices=CHANNELS)
    parser.add_argument("--expected-sha256", default=None, help="Digest from a separately trusted source")
    parser.add_argument("--expected-cert-sha256", default=None, help="Independently pinned publisher signing certificate")
    parser.add_argument("--store-local", action="store_true", help="Copy binary to ignored reference-apks/ within checkout")
    parser.add_argument("--run-rea", action="store_true", help="Run installed REA/JADX; evidence stays in ignored private-evidence/")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--catalog", type=Path, default=None)
    args = parser.parse_args()
    if not SLUG.fullmatch(args.slug) or not PACKAGE.fullmatch(args.package):
        parser.error("slug or Android package identifier invalid")
    if not args.name.strip() or not args.publisher.strip() or not args.version.strip():
        parser.error("name, publisher and version must not be empty")
    for url in (args.listing_url, args.download_url):
        if url is not None and (urlparse(url).scheme != "https" or not urlparse(url).hostname or urlparse(url).username):
            parser.error("source and listing URLs must use HTTPS with a hostname and no credentials")
    if args.source_type == "store_only" and args.download_url:
        parser.error("store_only must not claim an APK direct-download URL")
    for digest in (args.expected_sha256, args.expected_cert_sha256):
        if digest is not None and HEX64.fullmatch(digest.lower()) is None:
            parser.error("expected SHA-256 must be 64 hex characters")
    apk = args.apk.resolve(strict=True)
    size, digest = inspect_archive(apk)
    if args.expected_sha256 and args.expected_sha256.lower() != digest:
        raise ValueError("Downloaded APK SHA-256 does not match independently recorded digest")
    package = read_package(apk)
    if package is not None and package != args.package:
        raise ValueError("APK package identifier differs from expected package")
    # A signing check is only an authenticity claim if independently pinned.
    cert = read_signer(apk) if args.expected_cert_sha256 else None
    if args.expected_cert_sha256 and (cert is None or cert != args.expected_cert_sha256.lower()):
        raise ValueError("APK signing certificate unavailable or mismatched")

    root = args.repo_root.resolve(strict=True)
    catalog = args.catalog.resolve() if args.catalog is not None else root / "references/catalog.json"
    if args.store_local:
        store_dir = root / "reference-apks" / args.slug
        if store_dir.is_symlink() or (root / "reference-apks").is_symlink():
            raise ValueError("Local APK storage path must not be a symlink")
        store_dir.mkdir(parents=True, exist_ok=True)
        stored = store_dir / f"{digest}.apk"
        if stored.is_symlink():
            raise ValueError("Refusing symlink target for private reference")
        if not stored.exists():
            with tempfile.NamedTemporaryFile(dir=store_dir, delete=False) as temp:
                staging = Path(temp.name)
            try:
                shutil.copyfile(apk, staging)
                if sha256_file(staging) != digest:
                    raise ValueError("Copied reference changed during ingestion")
                staging.chmod(0o600)
                staging.replace(stored)
            finally:
                staging.unlink(missing_ok=True)
        if sha256_file(stored) != digest:
            raise ValueError("Stored reference checksum mismatch")
        apk_for_rea = stored
        local_location = f"reference-apks/{args.slug}/{digest}.apk"
    else:
        apk_for_rea = apk
        local_location = None

    evidence_location = None
    if args.run_rea:
        output = root / "private-evidence" / args.slug / f"{digest}-rea-package.json"
        run_rea(apk_for_rea, output)
        evidence_location = f"private-evidence/{args.slug}/{digest}-rea-package.json"

    # URL labels are operator assertions, NOT proof of publisher ownership.
    item = {
        "slug": args.slug, "name": args.name, "publisher": args.publisher,
        "package": args.package, "version": args.version,
        "listing_url": args.listing_url, "download_url": args.download_url,
        "source_type": args.source_type, "source_authenticity": "operator_claim_unverified",
        "sha256": digest, "size_bytes": size,
        "sha256_matched_supplied_pin": bool(args.expected_sha256),
        "package_checked_with_aapt": package is not None,
        "signer_sha256": cert, "signer_matched_supplied_pin": bool(args.expected_cert_sha256),
        "private_apk_path": local_location, "rea_private_evidence": evidence_location,
        "rea_status": "completed" if evidence_location else "not_run",
        "redistribution_rights": "not_verified",
        "recorded_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }
    if catalog.exists():
        document = json.loads(catalog.read_text(encoding="utf-8"))
        if document.get("schema_version") != 1 or not isinstance(document.get("references"), list):
            raise ValueError("Existing reference catalog has unsupported schema")
    else:
        document = {"schema_version": 1, "references": []}
    document["references"] = [
        row for row in document["references"]
        if not (row.get("slug") == args.slug and row.get("sha256") == digest)
    ] + [item]
    document["references"].sort(key=lambda row: (row.get("slug", ""), row.get("version", "")))
    catalog.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=catalog.parent, delete=False) as temp:
        intermediate = Path(temp.name)
        json.dump(document, temp, indent=2, ensure_ascii=False)
        temp.write("\n")
    intermediate.replace(catalog)
    print(json.dumps({
        "status": "catalogued", "slug": args.slug, "sha256": digest,
        "source_authenticity": item["source_authenticity"],
        "rea_status": item["rea_status"], "stored_locally": bool(local_location)
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(f"reference intake failed: {exc}", file=sys.stderr)
        sys.exit(1)
