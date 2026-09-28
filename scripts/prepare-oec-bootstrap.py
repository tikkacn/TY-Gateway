#!/usr/bin/env python3
"""Prepare a pinned first-install kit from a signed release.

The installer can consume the included signed TY Gateway artifacts and pinned
official DAE package locally, or download them from their configured sources.
OS dependencies still come from network sources. This is not a publisher or a
fully offline installer.
"""

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "scripts" / "bootstrap-oec.template.sh"
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
ARTIFACT_NAME = "ty-gateway-oec-overlay.tar.gz"
FETCH_NAME = "ty-release-fetch-linux-arm64"
DAE_NAME = "dae-linux-arm64-v2.1.1.deb"
DAE_SHA256 = "e7ecc9600df20163e90b9cab018f522e090996993c971ad0c271fb5b33c3a387"
PINNED_KEY_SHA256 = "78756e159ec392b52b146b049db79b0d94848ee10359841f58877aad192f1a3f"
R2_BASE_URL = "https://oec.uutec.net"


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def signed_manifest(bundle):
    envelope = json.loads(bundle.read_bytes())
    if not isinstance(envelope, dict) or set(envelope) != {"format_version", "manifest", "signature"}:
        raise ValueError("signed release envelope is invalid")
    manifest = json.loads(base64.b64decode(envelope["manifest"], validate=True))
    if manifest.get("channel") not in ("pilot", "stable") or not VERSION.fullmatch(manifest.get("version", "")):
        raise ValueError("signed release channel or version is invalid")
    if manifest.get("product") != "ty-gateway" or manifest.get("platform") != "linux-arm64":
        raise ValueError("signed release product or platform is invalid")
    if manifest.get("artifact") != f"releases/{manifest['version']}/{ARTIFACT_NAME}":
        raise ValueError("signed release artifact path is unexpected")
    return manifest


def check_fetch_matches_signed_archive(fetch, archive):
    header = fetch.read_bytes()[:20]
    if len(header) != 20 or header[:4] != b"\x7fELF" or header[4:6] != b"\x02\x01" or struct.unpack("<H", header[18:20])[0] != 183:
        raise ValueError("bootstrap verifier is not an ARM64 ELF binary")
    digest = sha256_file(fetch)
    matches = 0
    with tarfile.open(archive, "r:gz") as package:
        for member in package:
            if not member.isfile() or not member.name.endswith("/payload/usr/local/bin/ty-release-fetch"):
                continue
            if len(member.name.split("/")) != 6:
                raise ValueError("unexpected verifier path in signed overlay")
            matches += 1
            content = package.extractfile(member)
            if content is None:
                raise ValueError("signed overlay verifier is unreadable")
            with content:
                archived_hash = hashlib.sha256(content.read()).hexdigest()
            if archived_hash != digest:
                raise ValueError("bootstrap verifier differs from the signed overlay")
    if matches != 1:
        raise ValueError("signed overlay must contain exactly one verifier")
    return digest


def render_bootstrap_template(template, manifest, fetch_hash, public_key, enable_r2_fallback=False):
    if enable_r2_fallback and manifest["channel"] != "stable":
        raise ValueError("R2 fallback is reserved for stable releases; Pilot bootstraps must use GitHub only")
    version = manifest["version"]
    r2_release = f"{R2_BASE_URL}/releases/{version}" if enable_r2_fallback else ""
    r2_fetch = f"{R2_BASE_URL}/bootstrap/{version}/ty-release-fetch-linux-arm64" if enable_r2_fallback else ""
    replacements = {
        "@RELEASE_VERSION@": version,
        "@RELEASE_CHANNEL@": manifest["channel"],
        "@FETCH_SHA256@": fetch_hash,
        "@PUBLIC_KEY_BASE64@": base64.b64encode(public_key).decode("ascii"),
        "@R2_RELEASE_URL@": r2_release,
        "@R2_FETCH_URL@": r2_fetch,
    }
    for placeholder, value in replacements.items():
        template = template.replace(placeholder, value)
    if re.search(r"@[A-Z_]+@", template):
        raise ValueError("bootstrap template has unresolved placeholders")
    return template


def prepare(args):
    for source in (args.bundle, args.artifact, args.public_key, args.fetch, args.verifier, args.dae_package):
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"missing or unsafe input file: {source}")
    if args.artifact.name != ARTIFACT_NAME:
        raise ValueError("artifact filename is not the fixed release filename")
    if sha256_file(args.public_key) != PINNED_KEY_SHA256:
        raise ValueError("release public key does not match the pinned TY Gateway key")
    if args.dae_package.name != DAE_NAME or sha256_file(args.dae_package) != DAE_SHA256:
        raise ValueError("DAE package filename or SHA-256 does not match the pinned official ARM64 package")
    subprocess.run([str(args.verifier), "verify", "-bundle", str(args.bundle),
                    "-public-key", str(args.public_key), "-artifact", str(args.artifact)],
                   check=True, stdout=subprocess.DEVNULL)
    manifest = signed_manifest(args.bundle)
    fetch_hash = check_fetch_matches_signed_archive(args.fetch, args.artifact)
    script = render_bootstrap_template(
        TEMPLATE.read_text(encoding="utf-8"), manifest, fetch_hash,
        args.public_key.read_bytes(), enable_r2_fallback=args.enable_r2_fallback,
    )
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite output directory: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ty-bootstrap-", dir=output.parent) as temporary:
        stage = pathlib.Path(temporary)
        with (stage / "bootstrap-oec.sh").open("w", encoding="utf-8", newline="\n") as destination:
            destination.write(script)
        shutil.copyfile(args.fetch, stage / FETCH_NAME)
        shutil.copyfile(args.public_key, stage / "release-public.pem")
        shutil.copyfile(args.bundle, stage / "release.json")
        shutil.copyfile(args.artifact, stage / ARTIFACT_NAME)
        shutil.copyfile(args.dae_package, stage / DAE_NAME)
        sums = []
        for name in ("bootstrap-oec.sh", FETCH_NAME, "release-public.pem", "release.json", ARTIFACT_NAME, DAE_NAME):
            sums.append(f"{sha256_file(stage / name)}  {name}")
        (stage / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="ascii")
        os.chmod(stage / "bootstrap-oec.sh", 0o755)
        os.replace(stage, output)
    print(f"prepared pinned TY Gateway bootstrap kit for {manifest['channel']} {manifest['version']}: {output}")
    print("For local package use: bootstrap-oec.sh --package-dir <this directory>.")
    print("The installer still needs network access for apt dependencies. The TY Gateway and DAE payloads are bundled locally.")
    if args.enable_r2_fallback:
        print("Generated stable bootstrap with GitHub primary and TY Gateway R2 fallback.")
    else:
        print("Generated GitHub-only bootstrap; no R2 URLs are embedded.")
    print("NOT PUBLISHED. Fresh-device testing and source/package review are still required.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "artifact", "public-key", "fetch", "verifier", "dae-package", "output"):
        parser.add_argument("--" + name, required=True, type=pathlib.Path)
    parser.add_argument("--enable-r2-fallback", action="store_true",
                        help="embed TY Gateway R2 fallback URLs for a stable release only")
    prepare(parser.parse_args())


if __name__ == "__main__":
    main()
