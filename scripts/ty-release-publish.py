#!/usr/bin/env python3
"""Publish an already signed TY Gateway ARM64 release to its isolated R2 bucket.

This script never reads Guide's config, database, or environment file. It only
uses TY_R2_* environment variables supplied by its own protected job.
"""

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import struct
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request

BUCKET = "ty-gateway-releases"
ORIGIN = "https://oec.uutec.net"
MAX_ARTIFACT = 512 << 20
VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
ARCHIVE_NAME_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
MAX_EXPANDED = 1 << 30
MAX_ENTRIES = 2048
PINNED_PUBLIC_KEY_SHA256 = "78756e159ec392b52b146b049db79b0d94848ee10359841f58877aad192f1a3f"
PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----", b"-----BEGIN OPENSSH PRIVATE KEY-----",
)
FORBIDDEN_BASENAMES = {
    "credentials.json", "activation.json", "pending-enrollment.json",
    "subscription.raw", "agent.env", "local.env", "frpc.toml",
    ".r2.env", "signing-private.pem", "password.json",
}
ALLOWED_FILES = frozenset({
    "install-oec-overlay.sh", "restore-oec-overlay.sh", "README.md", "target.json",
    "overlay-manifest.json", "SHA256SUMS",
    "payload/usr/local/bin/ty-gateway-agent", "payload/usr/local/bin/ty-gateway-local",
    "payload/usr/local/bin/ty-release-fetch", "payload/usr/local/bin/frpc",
    "payload/usr/local/libexec/ty-gateway-update", "payload/usr/local/libexec/ty-gateway-update-service",
    "payload/usr/local/libexec/ty-gateway-dae-helper",
    "payload/usr/local/libexec/ty-gateway-dae-preflight", "payload/usr/local/libexec/ty-gateway-firstboot",
    "payload/usr/local/libexec/ty-gateway-network", "payload/usr/local/libexec/ty_gateway_lan.py",
    "payload/etc/NetworkManager/dispatcher.d/90-ty-gateway-dae-forwarding",
    "payload/etc/tmpfiles.d/ty-gateway-lan.conf",
    "payload/etc/systemd/system/ty-gateway-firstboot.service",
    "payload/etc/systemd/system/ty-gateway-agent.service",
    "payload/etc/systemd/system/ty-gateway-local.service",
    "payload/etc/systemd/system/ty-gateway-network.service",
    "payload/etc/systemd/system/ty-gateway-lan.service",
    "payload/etc/systemd/system/ty-gateway-dae-helper.service",
    "payload/etc/systemd/system/ty-gateway-update-recover.service",
    "payload/etc/systemd/system/ty-gateway-update-service.service",
    "payload/etc/systemd/system/dae.service.d/ty-gateway-forwarding.conf",
    "payload/etc/systemd/system/ty-frpc-rescue.service",
    "payload/etc/ty-gateway/agent.env.example", "payload/etc/ty-gateway/local.env.example",
    "payload/etc/ty-gateway/frpc.toml.example", "payload/etc/ty-gateway/release-public.pem",
})


def audit_overlay(artifact, expected_public_key=None):
    """Reject unsafe or credential-bearing payloads before any public upload."""
    required = {"install-oec-overlay.sh", "restore-oec-overlay.sh", "SHA256SUMS", "overlay-manifest.json",
                "payload/usr/local/bin/ty-gateway-agent", "payload/usr/local/bin/ty-release-fetch",
                "payload/usr/local/libexec/ty-gateway-update",
                "payload/usr/local/libexec/ty-gateway-update-service",
                "payload/etc/systemd/system/ty-gateway-update-recover.service",
                "payload/etc/systemd/system/ty-gateway-update-service.service",
                "payload/etc/ty-gateway/release-public.pem"}
    seen = set()
    root = None
    expanded = 0
    archived_public_key = None
    with tarfile.open(artifact, "r|gz") as archive:
        for count, member in enumerate(archive, 1):
            if count > MAX_ENTRIES:
                raise ValueError("overlay has too many entries")
            name = member.name.rstrip("/")
            parts = name.split("/")
            if (not name or not ARCHIVE_NAME_RE.fullmatch(name) or name.startswith("/") or
                    "\\" in name or any(part in ("", ".", "..") for part in parts) or
                    parts[0].startswith(".")):
                raise ValueError("overlay has an unsafe path")
            if root is None:
                root = parts[0]
            elif root != parts[0]:
                raise ValueError("overlay has multiple root directories")
            if name in seen:
                raise ValueError("overlay has duplicate entries")
            seen.add(name)
            if not (member.isdir() or member.isfile()):
                raise ValueError("overlay has a link or unsupported file type")
            if member.isdir():
                if member.size:
                    raise ValueError("overlay directory has a body")
                continue
            if len(parts) == 1 or member.size < 0 or member.size > MAX_EXPANDED - expanded:
                raise ValueError("overlay file is misplaced or too large")
            expanded += member.size
            relative = "/".join(parts[1:])
            basename = parts[-1]
            if relative not in ALLOWED_FILES:
                raise ValueError("overlay contains an unexpected file")
            if (basename in FORBIDDEN_BASENAMES or
                    basename.endswith((".key", ".p12", ".pfx", ".sqlite", ".db")) or
                    basename.endswith(".pem") and relative != "payload/etc/ty-gateway/release-public.pem" or
                    relative.startswith("payload/var/lib/")):
                raise ValueError("overlay contains device state or private material")
            required.discard(relative)
            content = archive.extractfile(member)
            if content is None:
                raise ValueError("overlay file could not be read")
            tail = b""
            key_bytes = bytearray() if relative == "payload/etc/ty-gateway/release-public.pem" else None
            with content:
                while chunk := content.read(1 << 20):
                    body = tail + chunk
                    if any(marker in body for marker in PRIVATE_MARKERS):
                        raise ValueError("overlay contains a private key")
                    tail = body[-64:]
                    if key_bytes is not None:
                        key_bytes.extend(chunk)
                        if len(key_bytes) > 16384:
                            raise ValueError("overlay release public key is too large")
            if key_bytes is not None:
                archived_public_key = bytes(key_bytes)
    if required:
        raise ValueError("overlay is missing required package files")
    if expected_public_key is not None and archived_public_key != expected_public_key:
        raise ValueError("overlay public key differs from release signing key")


def read_bundle(bundle_path):
    raw = pathlib.Path(bundle_path).read_bytes()
    if not raw or len(raw) > 32 << 10:
        raise ValueError("signed release bundle size is invalid")
    envelope = json.loads(raw)
    if not isinstance(envelope, dict) or set(envelope) != {"format_version", "manifest", "signature"}:
        raise ValueError("signed release bundle fields are invalid")
    manifest = json.loads(base64.b64decode(envelope["manifest"], validate=True))
    if not isinstance(manifest, dict):
        raise ValueError("release manifest is invalid")
    if manifest.get("product") != "ty-gateway" or manifest.get("platform") != "linux-arm64":
        raise ValueError("release product or platform mismatch")
    if manifest.get("channel") not in ("pilot", "stable") or not valid_version(manifest.get("version")):
        raise ValueError("release channel or version is invalid")
    expected = f"releases/{manifest['version']}/"
    artifact_key = manifest.get("artifact", "")
    if not isinstance(artifact_key, str) or not artifact_key.startswith(expected) or ".." in artifact_key or not artifact_key.endswith(".tar.gz"):
        raise ValueError("unsafe artifact path")
    if not isinstance(manifest.get("size"), int) or not 0 < manifest["size"] <= MAX_ARTIFACT:
        raise ValueError("artifact size is invalid")
    if not isinstance(manifest.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"]):
        raise ValueError("artifact hash is invalid")
    return raw, manifest


def verify_local(verifier, bundle_path, public_key, artifact):
    subprocess.run(
        [verifier, "verify", "-bundle", str(bundle_path), "-public-key", str(public_key), "-artifact", str(artifact)],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def object_exists(s3, key):
    try:
        s3.head_object(Bucket=BUCKET, Key=key)
        return True
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if str(code) in ("404", "NoSuchKey", "NotFound"):
            return False
        raise


def verify_public(key, expected_hash, expected_size):
    request = urllib.request.Request(f"{ORIGIN}/{key}", headers={
        "Accept-Encoding": "identity", "User-Agent": "TY-Gateway-Release-Publisher/1",
    })
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise RuntimeError(f"public readback failed: HTTP {response.status}")
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > expected_size:
                raise ValueError("public object is larger than expected")
            digest.update(chunk)
    if size != expected_size or digest.hexdigest() != expected_hash:
        raise ValueError("public readback hash or size mismatch")


def wait_for_public(key, expected_hash, expected_size):
    last_error = None
    for attempt in range(5):
        try:
            verify_public(key, expected_hash, expected_size)
            return
        except (OSError, ValueError, RuntimeError) as exc:
            last_error = exc
            if attempt < 4:
                time.sleep(min(2 ** attempt, 16))
    raise RuntimeError("public readback did not match the uploaded object") from last_error


def bootstrap_verifier_bytes(artifact):
    """Extract only the ARM64 verifier already covered by the signed archive."""
    matches = []
    try:
        package_context = tarfile.open(artifact, "r:gz")
    except tarfile.ReadError:
        # Test callers may exercise channel ordering with a stub artifact. The
        # command-line publisher rejects it earlier in audit_overlay().
        return None
    with package_context as package:
        for member in package:
            parts = member.name.rstrip("/").split("/")
            if len(parts) > 1 and "/".join(parts[1:]) == "payload/usr/local/bin/ty-release-fetch":
                if not member.isfile() or member.size <= 0 or member.size > 64 << 20:
                    raise ValueError("signed release verifier entry is invalid")
                matches.append(member)
        if len(matches) != 1:
            raise ValueError("signed release must contain exactly one bootstrap verifier")
        source = package.extractfile(matches[0])
        if source is None:
            raise ValueError("signed release verifier cannot be read")
        data = source.read((64 << 20) + 1)
    if len(data) != matches[0].size or len(data) > 64 << 20:
        raise ValueError("signed release verifier size is invalid")
    if (len(data) < 20 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01" or
            struct.unpack("<H", data[18:20])[0] != 183):
        raise ValueError("signed release verifier is not a little-endian ARM64 ELF")
    return data


def render_bootstrap(manifest, public_key, fetch_binary):
    template_path = pathlib.Path(__file__).with_name("bootstrap-oec.template.sh")
    template = template_path.read_text(encoding="utf-8")
    replacements = {
        "@RELEASE_VERSION@": manifest["version"],
        "@RELEASE_CHANNEL@": manifest["channel"],
        "@FETCH_SHA256@": hashlib.sha256(fetch_binary).hexdigest(),
        "@PUBLIC_KEY_BASE64@": base64.b64encode(public_key).decode("ascii"),
        "@R2_RELEASE_URL@": (
            f"https://oec.uutec.net/releases/{manifest['version']}"
            if manifest["channel"] == "stable" else ""
        ),
        "@R2_FETCH_URL@": (
            f"https://oec.uutec.net/bootstrap/{manifest['version']}/ty-release-fetch-linux-arm64"
            if manifest["channel"] == "stable" else ""
        ),
    }
    for placeholder, value in replacements.items():
        template = template.replace(placeholder, value)
    if re.search(r"@[A-Z_]+@", template):
        raise ValueError("bootstrap template has unresolved placeholders")
    return template.encode("utf-8")


def valid_version(value):
    return (isinstance(value, str) and len(value) <= 32 and VERSION_RE.fullmatch(value) is not None and
            all(int(part) <= 0xffffffff for part in value.split(".")))


def version_order(value):
    return tuple(int(part) for part in value.split("."))


def publish(s3, artifact, bundle_bytes, manifest, bootstrap_script=None):
    artifact_key = manifest["artifact"]
    # The signed channel is inside the manifest. Pilot and stable promotions
    # therefore need separate immutable objects even when sharing one archive.
    bundle_key = f"releases/{manifest['version']}/{manifest['channel']}/release.json"
    channel_key = f"channels/{manifest['channel']}/linux-arm64/latest.json"
    verifier = bootstrap_verifier_bytes(artifact)
    verifier_key = f"bootstrap/{manifest['version']}/ty-release-fetch-linux-arm64"
    verifier_hash = hashlib.sha256(verifier).hexdigest() if verifier is not None else ""
    if pathlib.Path(artifact).name != pathlib.PurePosixPath(artifact_key).name:
        raise ValueError("local archive name does not match the signed manifest")
    # The channel object is the only mutable release object. If the prior
    # version is malformed, fail closed instead of silently replacing it.
    if object_exists(s3, channel_key):
        previous = s3.get_object(Bucket=BUCKET, Key=channel_key)["Body"].read(32 << 10)
        previous_envelope = json.loads(previous)
        previous_manifest = json.loads(base64.b64decode(previous_envelope["manifest"], validate=True))
        previous_version = previous_manifest.get("version")
        if not valid_version(previous_version):
            raise ValueError("existing channel version is invalid")
        if version_order(previous_version) >= version_order(manifest["version"]):
            raise ValueError("refusing an unchanged or older channel version")

    # Existing immutable objects may be reused only after a public hash match.
    # This permits retry after interrupted publication and promotion from pilot
    # to stable without rewriting a versioned object.
    if not object_exists(s3, artifact_key):
        s3.upload_file(
            str(artifact), BUCKET, artifact_key,
            ExtraArgs={"ContentType": "application/gzip", "CacheControl": "public, max-age=31536000, immutable"},
        )
    wait_for_public(artifact_key, manifest["sha256"], manifest["size"])
    if not object_exists(s3, bundle_key):
        s3.put_object(
            Bucket=BUCKET, Key=bundle_key, Body=bundle_bytes,
            ContentType="application/json", CacheControl="public, max-age=31536000, immutable",
        )
    wait_for_public(bundle_key, hashlib.sha256(bundle_bytes).hexdigest(), len(bundle_bytes))
    if verifier is not None and not object_exists(s3, verifier_key):
        s3.put_object(
            Bucket=BUCKET, Key=verifier_key, Body=verifier,
            ContentType="application/octet-stream", CacheControl="public, max-age=31536000, immutable",
        )
    if verifier is not None:
        wait_for_public(verifier_key, verifier_hash, len(verifier))

    if bootstrap_script is not None:
        bootstrap_key = f"bootstrap/{manifest['version']}/bootstrap-oec.sh"
        bootstrap_hash = hashlib.sha256(bootstrap_script).hexdigest()
        if not object_exists(s3, bootstrap_key):
            s3.put_object(
                Bucket=BUCKET, Key=bootstrap_key, Body=bootstrap_script,
                ContentType="text/x-shellscript", CacheControl="public, max-age=31536000, immutable",
            )
        wait_for_public(bootstrap_key, bootstrap_hash, len(bootstrap_script))

    # Never advance the mutable channel pointer until both immutable objects
    # have been uploaded and read back through the real public domain.
    s3.put_object(
        Bucket=BUCKET, Key=channel_key, Body=bundle_bytes,
        ContentType="application/json", CacheControl="public, max-age=60, must-revalidate",
    )
    return channel_key


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=pathlib.Path)
    parser.add_argument("--bundle", required=True, type=pathlib.Path)
    parser.add_argument("--public-key", required=True, type=pathlib.Path)
    parser.add_argument("--verifier", required=True, type=pathlib.Path)
    parser.add_argument("--bootstrap-script", type=pathlib.Path, required=True,
                        help="generated, version-pinned bootstrap-oec.sh to mirror alongside the verifier")
    args = parser.parse_args(argv)
    for name in ("TY_R2_ACCESS_KEY_ID", "TY_R2_SECRET_ACCESS_KEY", "TY_R2_ENDPOINT"):
        if not os.environ.get(name):
            parser.error(f"missing {name}")
    verify_local(args.verifier, args.bundle, args.public_key, args.artifact)
    audit_overlay(args.artifact, args.public_key.read_bytes())
    if hashlib.sha256(args.public_key.read_bytes()).hexdigest() != PINNED_PUBLIC_KEY_SHA256:
        parser.error("release public key does not match the pinned TY Gateway key")
    bundle, manifest = read_bundle(args.bundle)
    if not args.artifact.is_file() or not args.public_key.is_file():
        parser.error("archive or public key is missing")
    try:
        import boto3
    except ImportError as exc:
        raise SystemExit("boto3 is required in the isolated publisher environment") from exc
    endpoint = os.environ["TY_R2_ENDPOINT"]
    endpoint_parts = urllib.parse.urlsplit(endpoint)
    if endpoint_parts.scheme != "https" or not endpoint_parts.hostname or endpoint_parts.path not in ("", "/") or endpoint_parts.query or endpoint_parts.fragment or endpoint_parts.username:
        parser.error("TY_R2_ENDPOINT must be an HTTPS S3 endpoint with no path")
    s3 = boto3.client(
        "s3", endpoint_url=endpoint,
        aws_access_key_id=os.environ["TY_R2_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["TY_R2_SECRET_ACCESS_KEY"],
        region_name="auto",
    )
    if (not args.bootstrap_script.is_file() or args.bootstrap_script.is_symlink() or
            args.bootstrap_script.stat().st_size <= 0 or args.bootstrap_script.stat().st_size > 256 << 10):
        parser.error("bootstrap script is missing, unsafe, or too large")
    bootstrap_bytes = args.bootstrap_script.read_bytes()
    fetch_binary = bootstrap_verifier_bytes(args.artifact)
    if fetch_binary is None or bootstrap_bytes != render_bootstrap(manifest, args.public_key.read_bytes(), fetch_binary):
        parser.error("bootstrap script does not match the pinned release and signed verifier")
    channel_key = publish(s3, args.artifact, bundle, manifest, bootstrap_bytes)
    print(f"published {manifest['version']} to {BUCKET}/{channel_key}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"publication failed without changing Guide distribution ({type(exc).__name__})", file=sys.stderr)
        sys.exit(1)
