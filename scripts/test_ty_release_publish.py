import base64
import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("publisher", pathlib.Path(__file__).with_name("ty-release-publish.py"))
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class MissingObject(Exception):
    response = {"Error": {"Code": "404"}}


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.calls = []

    def head_object(self, *, Bucket, Key):
        self.calls.append(("head", Bucket, Key))
        if Key not in self.objects:
            raise MissingObject()
        return {"ContentLength": len(self.objects[Key])}

    def upload_file(self, filename, bucket, key, ExtraArgs):
        self.calls.append(("upload", bucket, key))
        self.objects[key] = pathlib.Path(filename).read_bytes()

    def put_object(self, *, Bucket, Key, Body, **kwargs):
        self.calls.append(("put", Bucket, Key))
        self.objects[Key] = Body

    def get_object(self, *, Bucket, Key):
        self.calls.append(("get", Bucket, Key))
        return {"Body": io.BytesIO(self.objects[Key])}


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.artifact = pathlib.Path(self.tmp.name, "ty-gateway-oec-overlay.tar.gz")
        self.artifact.write_bytes(b"overlay")
        self.manifest = {
            "format_version": 1, "product": "ty-gateway", "channel": "pilot", "version": "0.7.0",
            "platform": "linux-arm64", "artifact": "releases/0.7.0/ty-gateway-oec-overlay.tar.gz",
            "size": 7, "sha256": hashlib.sha256(b"overlay").hexdigest(),
            "published_at": "2026-09-24T00:00:00Z",
        }
        self.bundle = json.dumps({
            "format_version": 1,
            "manifest": base64.b64encode(json.dumps(self.manifest).encode()).decode(),
            "signature": "signature-is-verified-by-go-tool-before-publish",
        }).encode()

    def test_publishes_only_isolated_bucket_and_channel_last(self):
        s3 = FakeS3()
        with mock.patch.object(publisher, "wait_for_public") as check:
            key = publisher.publish(s3, self.artifact, self.bundle, self.manifest)
        self.assertEqual(key, "channels/pilot/linux-arm64/latest.json")
        self.assertEqual(check.call_count, 2)
        self.assertEqual(s3.calls[-1], ("put", publisher.BUCKET, key))
        self.assertEqual({item[1] for item in s3.calls}, {"ty-gateway-releases"})

    def test_failed_readback_never_advances_channel(self):
        s3 = FakeS3()
        with mock.patch.object(publisher, "wait_for_public", side_effect=ValueError("bad CDN readback")):
            with self.assertRaises(ValueError):
                publisher.publish(s3, self.artifact, self.bundle, self.manifest)
        self.assertNotIn("channels/pilot/linux-arm64/latest.json", s3.objects)

    def test_rejects_downgrade(self):
        s3 = FakeS3()
        prior = dict(self.manifest, version="0.8.0")
        s3.objects["channels/pilot/linux-arm64/latest.json"] = json.dumps({
            "manifest": base64.b64encode(json.dumps(prior).encode()).decode(),
        }).encode()
        with mock.patch.object(publisher, "wait_for_public"):
            with self.assertRaisesRegex(ValueError, "older"):
                publisher.publish(s3, self.artifact, self.bundle, self.manifest)
        self.assertEqual(s3.calls[-1][0], "get")

    def test_existing_immutable_objects_are_verified_not_overwritten(self):
        s3 = FakeS3()
        s3.objects[self.manifest["artifact"]] = self.artifact.read_bytes()
        s3.objects["releases/0.7.0/pilot/release.json"] = self.bundle
        with mock.patch.object(publisher, "wait_for_public") as check:
            publisher.publish(s3, self.artifact, self.bundle, self.manifest)
        self.assertEqual(check.call_count, 2)
        self.assertEqual([c for c in s3.calls if c[0] == "upload"], [])
        self.assertEqual([c for c in s3.calls if c[0] == "put"], [
            ("put", publisher.BUCKET, "channels/pilot/linux-arm64/latest.json")
        ])

    def test_pilot_to_stable_uses_distinct_signed_manifests(self):
        s3 = FakeS3()
        with mock.patch.object(publisher, "wait_for_public"):
            publisher.publish(s3, self.artifact, self.bundle, self.manifest)
            stable = dict(self.manifest, channel="stable")
            stable_bundle = b"stable-signed-bundle"
            publisher.publish(s3, self.artifact, stable_bundle, stable)
        self.assertIn("releases/0.7.0/pilot/release.json", s3.objects)
        self.assertEqual(s3.objects["releases/0.7.0/stable/release.json"], stable_bundle)
        self.assertEqual(len([c for c in s3.calls if c[0] == "upload"]), 1)

    def test_bundle_path_validation(self):
        bundle_file = pathlib.Path(self.tmp.name, "release.json")
        bundle_file.write_bytes(self.bundle)
        raw, manifest = publisher.read_bundle(bundle_file)
        self.assertEqual(raw, self.bundle)
        self.assertEqual(manifest["artifact"], self.manifest["artifact"])
        unsafe = dict(self.manifest, artifact="releases/0.7.0/../secret.tar.gz")
        bundle_file.write_bytes(json.dumps({
            "format_version": 1, "manifest": base64.b64encode(json.dumps(unsafe).encode()).decode(),
            "signature": "x",
        }).encode())
        with self.assertRaisesRegex(ValueError, "unsafe"):
            publisher.read_bundle(bundle_file)

    def test_version_validation_matches_device(self):
        self.assertTrue(publisher.valid_version("0.7.0"))
        self.assertTrue(publisher.valid_version("4294967295.0.0"))
        for value in ("01.2.3", "1.02.3", "1.2.003", "4294967296.0.0", "1.2", "../1.0.0"):
            with self.subTest(version=value):
                self.assertFalse(publisher.valid_version(value))

    def test_public_readback_has_explicit_user_agent(self):
        response = mock.MagicMock()
        response.__enter__.return_value.status = 200
        response.__enter__.return_value.read.side_effect = [b"signed", b""]
        with mock.patch.object(publisher.urllib.request, "urlopen", return_value=response) as opener:
            publisher.verify_public("releases/0.7.0/test.tar.gz", hashlib.sha256(b"signed").hexdigest(), 6)
        request = opener.call_args.args[0]
        self.assertEqual(request.get_header("User-agent"), "TY-Gateway-Release-Publisher/1")

    def write_overlay(self, extras=()):
        entries = [
            ("oec-overlay/install-oec-overlay.sh", b"#!/bin/sh\nexit 0\n", None),
            ("oec-overlay/restore-oec-overlay.sh", b"#!/bin/sh\nexit 0\n", None),
            ("oec-overlay/SHA256SUMS", b"checksums\n", None),
            ("oec-overlay/overlay-manifest.json", b"{}\n", None),
            ("oec-overlay/payload/usr/local/bin/ty-gateway-agent", b"agent", None),
            ("oec-overlay/payload/usr/local/bin/ty-release-fetch", b"fetch", None),
            ("oec-overlay/payload/usr/local/libexec/ty-gateway-update", b"updater", None),
            ("oec-overlay/payload/usr/local/libexec/ty-gateway-update-service", b"update service", None),
            ("oec-overlay/payload/etc/systemd/system/ty-gateway-update-recover.service", b"recover unit", None),
            ("oec-overlay/payload/etc/systemd/system/ty-gateway-update-service.service", b"update unit", None),
            ("oec-overlay/payload/etc/ty-gateway/release-public.pem", b"public key", None),
        ] + list(extras)
        with tarfile.open(self.artifact, "w:gz") as archive:
            for name, body, link in entries:
                info = tarfile.TarInfo(name)
                if link is not None:
                    info.type = tarfile.SYMTYPE
                    info.linkname = link
                else:
                    info.size = len(body)
                archive.addfile(info, None if link is not None else io.BytesIO(body))

    def test_overlay_audit_accepts_generic_package(self):
        self.write_overlay(extras=[("oec-overlay/payload/etc/ty-gateway/agent.env.example", b"TY_SERVER_URL=https://example.test\n", None)])
        publisher.audit_overlay(self.artifact)

    def test_overlay_audit_rejects_sensitive_or_unsafe_payload(self):
        cases = [
            ("oec-overlay/payload/etc/ty-gateway/frpc.toml", b"token=bad", None),
            ("oec-overlay/payload/etc/ty-gateway/release-public.pem", b"-----BEGIN PRIVATE KEY-----", None),
            ("oec-overlay/payload/etc/ty-gateway/credentials.json", b"{}", None),
            ("oec-overlay/../outside", b"bad", None),
            ("oec-overlay/payload/link", b"", "../../outside"),
        ]
        for extra in cases:
            with self.subTest(path=extra[0]):
                self.write_overlay(extras=[extra])
                with self.assertRaises(ValueError):
                    publisher.audit_overlay(self.artifact)


if __name__ == "__main__":
    unittest.main()
