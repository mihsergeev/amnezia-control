import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import acontrol_update_verify as verifier


VERSION = "1.2.3"
TAG = f"v{VERSION}"
REF = f"refs/tags/{TAG}"
COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40


def image_index(service):
    return json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"digest": "sha256:" + "a" * 64, "platform": {"os": "linux", "architecture": "amd64"}},
            {"digest": "sha256:" + "b" * 64, "platform": {"os": "linux", "architecture": "arm64"}},
        ],
        "annotations": {"org.opencontainers.image.title": service},
    }).encode()


def proof(service, digest):
    workflow = f"{verifier._WORKFLOW}@{REF}"
    return {
        "verificationResult": {
            "signature": {"certificate": {
                "issuer": "https://token.actions.githubusercontent.com",
                "subjectAlternativeName": workflow,
                "buildTrigger": "release",
                "buildSignerURI": workflow,
                "buildSignerDigest": COMMIT,
                "buildConfigURI": workflow,
                "buildConfigDigest": COMMIT,
                "runnerEnvironment": "github-hosted",
                "sourceRepositoryURI": "https://github.com/mihsergeev/amnezia-control",
                "sourceRepositoryIdentifier": "1292799501",
                "sourceRepositoryOwnerIdentifier": "71547423",
                "sourceRepositoryRef": REF,
                "sourceRepositoryDigest": COMMIT,
                "sourceRepositoryVisibilityAtSigning": "public",
            }},
            "statement": {
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": verifier._IMAGE_REPOS[service], "digest": {"sha256": digest[7:]}}],
            },
        },
    }


class VerifyReleaseTests(unittest.TestCase):
    def setUp(self):
        self.indexes = {service: image_index(service) for service in ("backend", "frontend")}
        self.digests = {service: "sha256:" + hashlib.sha256(raw).hexdigest() for service, raw in self.indexes.items()}
        self.release = {
            "id": 123, "draft": False, "prerelease": False, "tag_name": TAG,
            "published_at": "2026-11-27T10:00:00Z", "target_commitish": "main",
        }
        self.tag = {"ref": REF, "object": {"type": "commit", "sha": COMMIT}}
        self.repo = {"id": 1292799501, "owner": {"id": 71547423}, "full_name": verifier._REPO,
                     "private": False, "fork": False}
        self.proofs = {service: proof(service, digest) for service, digest in self.digests.items()}
        self.checked = []

    def github(self, path, description, *, limit=None):
        if not path:
            return self.repo
        if path == "/releases/latest":
            return self.release
        if path == f"/git/ref/tags/{TAG}":
            return self.tag
        if path == f"/git/tags/{OTHER_COMMIT}":
            return {"sha": OTHER_COMMIT, "object": {"type": "commit", "sha": COMMIT}}
        if path in (f"/attestations/{digest}" for digest in self.digests.values()):
            return {"attestations": [{"bundle": {"mediaType": "bundle"}}]}
        self.fail(f"Unexpected GitHub path {path}")

    def command(self, command, work, env, *, timeout, limit, description):
        self.assertNotIn("GH_TOKEN", env)
        self.assertNotIn("HTTPS_PROXY", env)
        if command[0] == "/usr/bin/docker":
            for service, image in verifier._IMAGE_REPOS.items():
                if command == ["/usr/bin/docker", "buildx", "imagetools", "inspect", "--raw", f"{image}:{VERSION}"]:
                    return self.indexes[service]
            self.fail(f"Unexpected Docker operation {command[1:]}")
        self.assertEqual(command[:3], ["/usr/bin/gh", "attestation", "verify"])
        self.assertEqual(command[command.index("--source-digest") + 1], COMMIT)
        self.assertEqual(command[command.index("--signer-digest") + 1], COMMIT)
        self.assertEqual(command[command.index("--source-ref") + 1], REF)
        self.assertEqual(command[command.index("--cert-identity") + 1], f"{verifier._WORKFLOW}@{REF}")
        self.assertIn("--deny-self-hosted-runners", command)
        for service, image in verifier._IMAGE_REPOS.items():
            if command[3] == f"oci://{image}@{self.digests[service]}":
                bundle = Path(command[command.index("--bundle") + 1])
                self.assertEqual(bundle.parent, work)
                self.assertEqual(bundle.name, f"{service}.jsonl")
                self.assertEqual(json.loads(bundle.read_bytes()), {"mediaType": "bundle"})
                self.checked.append(service)
                return json.dumps([self.proofs[service]]).encode()
        self.fail(f"Unexpected attestation subject {command[3]}")

    def verify(self, version=VERSION):
        with patch.object(verifier, "_github", side_effect=self.github), \
                patch.object(verifier, "_command_output", side_effect=self.command):
            return verifier.verify_release(version)

    def test_verified_pair_using_annotated_tag(self):
        self.tag["object"] = {"type": "tag", "sha": OTHER_COMMIT}
        refs, commit = self.verify(TAG)
        self.assertEqual(commit, COMMIT)
        self.assertEqual(refs, {
            "backend": f"ghcr.io/mihsergeev/amnezia-control-backend@{self.digests['backend']}",
            "frontend": f"ghcr.io/mihsergeev/amnezia-control-frontend@{self.digests['frontend']}",
        })
        self.assertEqual(self.checked, ["backend", "frontend"])

    def test_stale_or_non_public_release_fails_before_docker(self):
        for changes in ({"tag_name": "v1.2.4"}, {"draft": True}, {"prerelease": True}, {"published_at": None}):
            with self.subTest(changes=changes), patch.dict(self.release, changes):
                with self.assertRaisesRegex(verifier.ReleaseVerificationError, "latest published"):
                    self.verify()
        self.assertEqual(self.checked, [])

    def test_changed_repository_identity_fails(self):
        self.repo["id"] += 1
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "repository identity"):
            self.verify()

    def test_bad_input_reaches_no_remote(self):
        with patch.object(verifier, "_github") as get:
            for value in (None, "latest", "1.2.3-rc1", "01.2.3", "1.2.100000000", "v1.2.3\n"):
                with self.subTest(value=value), self.assertRaises(verifier.ReleaseVerificationError):
                    verifier.verify_release(value)
            get.assert_not_called()

    def test_unsigned_frontend_cannot_pass_backend_proof(self):
        self.proofs["frontend"] = self.proofs["backend"]
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "frontend build provenance"):
            self.verify()
        self.assertEqual(self.checked, ["backend", "frontend"])

    def test_changed_latest_release_after_proofs_fails(self):
        command = self.command

        def race(*args, **kwargs):
            output = command(*args, **kwargs)
            if self.checked == ["backend", "frontend"]:
                self.release["id"] = 456
            return output

        self.command = race
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "release changed"):
            self.verify()

    def test_changed_image_tag_after_proofs_fails(self):
        command = self.command

        def race(*args, **kwargs):
            output = command(*args, **kwargs)
            if self.checked == ["backend", "frontend"]:
                self.indexes["frontend"] = image_index("replaced")
            return output

        self.command = race
        with self.assertRaisesRegex(verifier.ReleaseVerificationError, "image tag changed"):
            self.verify()

    def test_matching_certificate_requires_signed_release_identity(self):
        digest = self.digests["backend"]
        original = self.proofs["backend"]
        for field, value in {
            "buildTrigger": "workflow_dispatch",
            "runnerEnvironment": "self-hosted",
            "sourceRepositoryIdentifier": "123",
            "sourceRepositoryOwnerIdentifier": "123",
            "sourceRepositoryRef": "refs/heads/main",
            "sourceRepositoryDigest": OTHER_COMMIT,
            "buildSignerDigest": OTHER_COMMIT,
            "buildSignerURI": f"{verifier._WORKFLOW}@refs/heads/main",
        }.items():
            with self.subTest(field=field):
                altered = copy.deepcopy(original)
                altered["verificationResult"]["signature"]["certificate"][field] = value
                self.assertFalse(verifier._matching_proof(altered, verifier._IMAGE_REPOS["backend"], digest, REF, COMMIT))

    def test_config_source_path_is_closed(self):
        with patch.object(verifier, "_fetch", return_value=b"services: {}\n") as fetch:
            self.assertEqual(verifier.download_source_file(COMMIT, "compose.yml"), b"services: {}\n")
            fetch.assert_called_once_with(
                f"https://raw.githubusercontent.com/mihsergeev/amnezia-control/{COMMIT}/compose.yml",
                "runtime source file", {}, 128 * 1024,
            )
        with patch.object(verifier, "_fetch") as fetch:
            for ref, path in (("main", "compose.yml"), (TAG, "README.md"), (COMMIT, "../compose.yml")):
                with self.subTest(ref=ref, path=path), self.assertRaises(verifier.ReleaseVerificationError):
                    verifier.download_source_file(ref, path)
            fetch.assert_not_called()

    def test_download_limit_applies_to_streamed_content(self):
        response = io.BytesIO(b"excessive")
        response.status = 200
        response.headers = {}
        with patch.object(verifier, "build_opener") as build:
            build.return_value.open.return_value = response
            with self.assertRaisesRegex(verifier.ReleaseVerificationError, "Response too large"):
                verifier._github("/releases/latest", "latest release", limit=4)
            proxy, redirects = build.call_args.args
            self.assertEqual(proxy.proxies, {})
            self.assertIsNone(redirects.redirect_request(None, None, 302, "", {}, "https://example.com"))


if __name__ == "__main__":
    unittest.main()
