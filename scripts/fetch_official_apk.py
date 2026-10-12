#!/usr/bin/env python3
"""Fetch a publisher-approved HTTPS APK into ignored private storage."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import socket
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
MAX_APK_BYTES = 2 * 1024**3


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def checked_url(value: str, allowed_hosts: set[str]) -> str:
    try:
        uri = urlsplit(value)
        host = (uri.hostname or "").lower().rstrip(".")
        port = uri.port
    except ValueError as exc:
        raise ValueError("Invalid direct APK URL") from exc
    if uri.scheme != "https" or not host or uri.username or uri.password or port not in (None, 443):
        raise ValueError("Only credential-free HTTPS URLs on port 443 are allowed")
    if host not in allowed_hosts or host == "localhost" or host.endswith(".localhost"):
        raise ValueError("APK URL or redirect host not explicitly approved")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return value
    if not ip.is_global:
        raise ValueError("Local, private or reserved IP address not allowed")
    return value


def public_dns(host: str) -> None:
    for address in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
        ip = ipaddress.ip_address(address[4][0].split("%", 1)[0])
        if not ip.is_global:
            raise ValueError("Publisher host resolves to a non-public address")


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]):
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        checked_url(newurl, self.allowed_hosts)
        public_dns(urlsplit(newurl).hostname)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="Direct publisher APK download, not a Play Store page")
    parser.add_argument("--sha256", required=True, help="Expected SHA-256 from a trusted independent source")
    parser.add_argument("--slug", required=True, help="Reference catalog identifier")
    parser.add_argument("--allow-redirect-host", action="append", default=[], help="Explicit trusted publisher CDN host")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--dry-run", action="store_true", help="Validate input without contacting a server")
    args = parser.parse_args()
    if SLUG.fullmatch(args.slug) is None or SHA_RE.fullmatch(args.sha256.lower()) is None:
        parser.error("Invalid slug or SHA-256")
    root = args.repo_root.resolve(strict=True)
    origin_host = (urlsplit(args.url).hostname or "").lower().rstrip(".")
    hosts = {origin_host}
    for host in args.allow_redirect_host:
        if re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", host) is None:
            parser.error("Invalid redirect hostname")
        hosts.add(host.lower().rstrip("."))
    checked_url(args.url, hosts)
    folder = root / "reference-apks" / args.slug
    if (root / "reference-apks").is_symlink() or folder.is_symlink():
        raise ValueError("Private APK store must not use symlinks")
    destination = folder / f"{args.sha256.lower()}.apk"
    if destination.is_symlink():
        raise ValueError("Refusing symlinked APK target")
    if args.dry_run:
        print(json.dumps({"status": "preflight_only", "approved_hosts": sorted(hosts), "network_used": False}))
        return 0
    if destination.is_file():
        existing = file_hash(destination)
        if existing != args.sha256.lower():
            raise ValueError("Existing reference APK digest mismatch")
        print(json.dumps({"status": "already_verified", "private_path": str(destination.relative_to(root)), "sha256": existing}))
        return 0

    # Host attribution and independent checksum provenance are operator-reviewed.
    for host in hosts:
        public_dns(host)
    folder.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), SafeRedirect(hosts))
    request = urllib.request.Request(args.url, headers={"User-Agent": "ApplicationReferenceResearch/1.0"})
    staged = None
    try:
        with tempfile.NamedTemporaryFile(dir=folder, delete=False) as stream:
            staged = Path(stream.name)
            digest = hashlib.sha256()
            total = 0
            started = time.monotonic()
            with opener.open(request, timeout=30) as response:
                checked_url(response.url, hosts)
                length = response.headers.get("Content-Length")
                if length and int(length) > MAX_APK_BYTES:
                    raise ValueError("Remote APK exceeds maximum allowed size")
                while True:
                    if time.monotonic() - started > 240:
                        raise TimeoutError("APK download deadline exceeded")
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > MAX_APK_BYTES:
                        raise ValueError("Remote APK exceeds maximum allowed size")
                    stream.write(block)
                    digest.update(block)
        if digest.hexdigest() != args.sha256.lower():
            raise ValueError("APK SHA-256 differs from supplied expected digest")
        if not zipfile.is_zipfile(staged):
            raise ValueError("Downloaded file is not an APK ZIP archive")
        with zipfile.ZipFile(staged) as archive:
            if "AndroidManifest.xml" not in archive.namelist():
                raise ValueError("Downloaded ZIP has no AndroidManifest.xml")
        staged.chmod(0o600)
        staged.replace(destination)
        print(json.dumps({
            "status": "downloaded_verified_hash", "private_path": str(destination.relative_to(root)),
            "sha256": digest.hexdigest(), "size_bytes": total,
            "publisher_identity": "operator_claim_unverified"
        }, sort_keys=True))
        return 0
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, TimeoutError, zipfile.BadZipFile) as exc:
        print(f"publisher APK download failed: {exc}", file=sys.stderr)
        sys.exit(1)
