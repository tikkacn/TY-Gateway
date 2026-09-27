#!/usr/bin/env python3
"""Prepare an unpublished, credential-free first-install kit from a signed release.

The output is NOT a publisher. Review and test it on a fresh ARM64 device before
putting its installer/verifier on GitHub or the isolated TY Gateway R2 bucket.
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
PINNED_KEY_SHA256 = "78756e159ec392b52b146b049db79b0d94848ee10359841f58877aad192f1a3f"


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


def prepare(args):
    for source in (args.bundle, args.artifact, args.public_key, args.fetch, args.verifier):
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"missing or unsafe input file: {source}")
    if args.artifact.name != ARTIFACT_NAME:
        raise ValueError("artifact filename is not the fixed release filename")
    if sha256_file(args.public_key) != PINNED_KEY_SHA256:
        raise ValueError("release public key does not match the pinned TY Gateway key")
    subprocess.run([str(args.verifier), "verify", "-bundle", str(args.bundle),
                    "-public-key", str(args.public_key), "-artifact", str(args.artifact)],
                   check=True, stdout=subprocess.DEVNULL)
    manifest = signed_manifest(args.bundle)
    fetch_hash = check_fetch_matches_signed_archive(args.fetch, args.artifact)
    script = TEMPLATE.read_text(encoding="utf-8")
    script = script.replace("@RELEASE_VERSION@", manifest["version"])
    script = script.replace("@FETCH_SHA256@", fetch_hash)
    script = script.replace("@PUBLIC_KEY_BASE64@", base64.b64encode(args.public_key.read_bytes()).decode("ascii"))
    if "@RELEASE_VERSION@" in script or "@FETCH_SHA256@" in script or "@PUBLIC_KEY_BASE64@" in script:
        raise ValueError("bootstrap template has unresolved placeholders")
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite output directory: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ty-bootstrap-", dir=output.parent) as temporary:
        stage = pathlib.Path(temporary)
        (stage / "bootstrap-oec.sh").write_text(script, encoding="utf-8", newline="\n")
        shutil.copyfile(args.fetch, stage / FETCH_NAME)
        shutil.copyfile(args.public_key, stage / "release-public.pem")
        shutil.copyfile(args.bundle, stage / "release.json")
        shutil.copyfile(args.artifact, stage / ARTIFACT_NAME)
        sums = []
        for name in ("bootstrap-oec.sh", FETCH_NAME, "release-public.pem", "release.json", ARTIFACT_NAME):
            sums.append(f"{sha256_file(stage / name)}  {name}")
        (stage / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="ascii")
        os.chmod(stage / "bootstrap-oec.sh", 0o755)
        os.replace(stage, output)
    print(f"prepared {manifest['channel']} {manifest['version']} offline kit: {output}")
    print("NOT PUBLISHED. Fresh-device testing and source/package review are still required.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "artifact", "public-key", "fetch", "verifier", "output"):
        parser.add_argument("--" + name, required=True, type=pathlib.Path)
    prepare(parser.parse_args())


if __name__ == "__main__":
    main()
