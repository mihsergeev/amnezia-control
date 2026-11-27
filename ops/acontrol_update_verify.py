"""Verify the current public release on the host before pulling any images."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
from time import monotonic
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


_REPO = "mihsergeev/amnezia-control"
_REPO_ID = 1292799501
_OWNER_ID = 71547423
_REPO_URL = f"https://github.com/{_REPO}"
_REPO_API = f"https://api.github.com/repos/{_REPO}"
_RAW_REPO = f"https://raw.githubusercontent.com/{_REPO}"
_WORKFLOW = f"{_REPO_URL}/.github/workflows/release-images.yml"
_PROVENANCE = "https://slsa.dev/provenance/v1"
_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
_SOURCE_FILES = {"compose.yml", "compose.tls.yml", "compose.caddy.yml", "deploy/Caddyfile"}
_IMAGE_REPOS = {
    "backend": f"ghcr.io/{_REPO}-backend",
    "frontend": f"ghcr.io/{_REPO}-frontend",
}
_VERSION = re.compile(r"(?:0|[1-9][0-9]{0,7})(?:\.(?:0|[1-9][0-9]{0,7})){2}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_PUBLISHED_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_HTTP_TIMEOUT = 12
_MANIFEST_LIMIT = 64 * 1024
_SOURCE_LIMIT = 128 * 1024
_METADATA_LIMIT = 256 * 1024
_BUNDLE_LIMIT = 1024 * 1024
_VERIFICATION_LIMIT = 4 * 1024 * 1024
_MAX_TAG_OBJECTS = 4
_MAX_BUNDLES = 16


class ReleaseVerificationError(ValueError):
    """A release could not be verified from its public metadata and attestations."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _object(value):
    return value if isinstance(value, dict) else {}


def _json(payload: bytes, description: str):
    try:
        return json.loads(payload.decode("utf-8"))
    except (ValueError, RecursionError):
        raise ReleaseVerificationError(f"Invalid {description} JSON") from None


def _fetch(url: str, description: str, headers: dict[str, str], limit: int) -> bytes:
    request = Request(url, headers={
        "User-Agent": "amnezia-control-host-updater",
        "Accept-Encoding": "identity",
        "Cache-Control": "no-cache",
        **headers,
    })
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    deadline = monotonic() + _HTTP_TIMEOUT
    payload = bytearray()
    try:
        with opener.open(request, timeout=_HTTP_TIMEOUT) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise ReleaseVerificationError(f"Unexpected response for {description}")
            while True:
                if monotonic() >= deadline:
                    raise ReleaseVerificationError(f"Timed out retrieving {description}")
                chunk = response.read1(min(65536, limit + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > limit:
                    raise ReleaseVerificationError(f"Response too large for {description}")
    except (OSError, http.client.HTTPException):
        raise ReleaseVerificationError(f"Could not retrieve {description} from GitHub") from None
    if monotonic() >= deadline:
        raise ReleaseVerificationError(f"Timed out retrieving {description}")
    return bytes(payload)


def _github(path: str, description: str, *, limit: int = _METADATA_LIMIT) -> dict:
    payload = _fetch(_REPO_API + path, description, {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }, limit)
    result = _json(payload, description)
    if not isinstance(result, dict):
        raise ReleaseVerificationError(f"Unexpected JSON for {description}")
    return result


def _validate_repository() -> None:
    repo = _github("", "official repository")
    repo_id = repo.get("id")
    owner_id = _object(repo.get("owner")).get("id")
    if (
        repo.get("full_name") != _REPO
        or type(repo_id) is not int or repo_id != _REPO_ID
        or type(owner_id) is not int or owner_id != _OWNER_ID
        or repo.get("private") is not False
        or repo.get("fork") is not False
    ):
        raise ReleaseVerificationError("Official repository identity mismatch")


def _latest_release(tag: str) -> int:
    release = _github("/releases/latest", "latest release")
    release_id = release.get("id")
    published_at = release.get("published_at")
    if (
        release.get("tag_name") != tag
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or type(release_id) is not int
        or release_id <= 0
        or not isinstance(published_at, str)
        or not _PUBLISHED_AT.fullmatch(published_at)
    ):
        raise ReleaseVerificationError("Requested version is not the latest published stable release")
    return release_id


def _git_object(value) -> tuple[str, str]:
    value = _object(value)
    kind, sha = value.get("type"), value.get("sha")
    if kind not in ("commit", "tag") or not isinstance(sha, str) or not _COMMIT.fullmatch(sha):
        raise ReleaseVerificationError("Invalid release tag object")
    return kind, sha


def _tag_source(tag: str) -> tuple[str, str]:
    result = _github(f"/git/ref/tags/{tag}", "release tag")
    if result.get("ref") != f"refs/tags/{tag}":
        raise ReleaseVerificationError("Release tag ref mismatch")
    kind, sha = _git_object(result.get("object"))
    ref_sha = sha
    for _ in range(_MAX_TAG_OBJECTS):
        if kind == "commit":
            return ref_sha, sha
        annotated = _github(f"/git/tags/{sha}", "annotated release tag")
        if annotated.get("sha") != sha:
            raise ReleaseVerificationError("Annotated release tag identity mismatch")
        kind, sha = _git_object(annotated.get("object"))
    if kind != "commit":
        raise ReleaseVerificationError("Too many nested annotated release tags")
    return ref_sha, sha


def _command_output(
    command: list[str], work: Path, env: dict[str, str], *, timeout: int, limit: int, description: str,
) -> bytes:
    deadline = monotonic() + timeout
    payload = bytearray()
    try:
        with subprocess.Popen(
            command, cwd=work, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True,
        ) as process:
            try:
                assert process.stdout is not None
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise subprocess.TimeoutExpired(command, timeout)
                        chunk = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(payload)))
                        if not chunk:
                            break
                        payload.extend(chunk)
                        if len(payload) > limit:
                            raise ReleaseVerificationError(f"Output too large for {description}")
                if process.wait(timeout=max(0, deadline - monotonic())) != 0:
                    raise ReleaseVerificationError(f"Failed to verify {description}")
            except BaseException:
                # The Docker CLI may have spawned a Buildx plugin that also holds the pipe.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                raise
    except subprocess.TimeoutExpired:
        raise ReleaseVerificationError(f"Timed out verifying {description}") from None
    except OSError:
        raise ReleaseVerificationError(f"Could not run verifier for {description}") from None
    return bytes(payload)


def _clean_environment(work: Path) -> dict[str, str]:
    env = {"PATH": "/usr/bin:/bin", "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1"}
    for name in ("HOME", "GH_CONFIG_DIR", "XDG_CACHE_HOME", "DOCKER_CONFIG"):
        directory = work / name.lower()
        directory.mkdir(mode=0o700)
        env[name] = str(directory)
    return env


def _image_digest(service: str, version: str, work: Path, env: dict[str, str]) -> str:
    description = f"{service} image index"
    raw = _command_output(
        ["/usr/bin/docker", "buildx", "imagetools", "inspect", "--raw", f"{_IMAGE_REPOS[service]}:{version}"],
        work, env, timeout=25, limit=_MANIFEST_LIMIT, description=description,
    )
    index = _object(_json(raw, description))
    manifests = index.get("manifests")
    if (
        index.get("schemaVersion") != 2
        or index.get("mediaType") not in (
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        )
        or not isinstance(manifests, list)
    ):
        raise ReleaseVerificationError(f"Invalid {description}")
    platforms = []
    for item in manifests:
        descriptor = _object(item)
        platform = _object(descriptor.get("platform"))
        arch = platform.get("architecture")
        if platform.get("os") != "linux" or arch not in ("amd64", "arm64"):
            continue
        digest = descriptor.get("digest")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ReleaseVerificationError(f"Invalid platform digest in {description}")
        platforms.append(arch)
    if sorted(platforms) != ["amd64", "arm64"]:
        raise ReleaseVerificationError(f"Ambiguous or missing release platforms in {description}")
    # Buildx --raw returns the exact registry bytes, with no appended newline.
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _matching_proof(row, image: str, digest: str, ref: str, commit: str) -> bool:
    result = _object(_object(row).get("verificationResult"))
    certificate = _object(_object(result.get("signature")).get("certificate"))
    expected = {
        "issuer": _OIDC_ISSUER,
        "subjectAlternativeName": f"{_WORKFLOW}@{ref}",
        "buildTrigger": "release",
        "buildSignerURI": f"{_WORKFLOW}@{ref}",
        "buildSignerDigest": commit,
        "buildConfigURI": f"{_WORKFLOW}@{ref}",
        "buildConfigDigest": commit,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryURI": _REPO_URL,
        "sourceRepositoryIdentifier": str(_REPO_ID),
        "sourceRepositoryOwnerIdentifier": str(_OWNER_ID),
        "sourceRepositoryRef": ref,
        "sourceRepositoryDigest": commit,
        "sourceRepositoryVisibilityAtSigning": "public",
    }
    if any(certificate.get(key) != value for key, value in expected.items()):
        return False
    statement = _object(result.get("statement"))
    subjects = statement.get("subject")
    if statement.get("predicateType") != _PROVENANCE or not isinstance(subjects, list):
        return False
    for item in subjects:
        subject = _object(item)
        if subject.get("name") == image and _object(subject.get("digest")).get("sha256") == digest[7:]:
            return True
    return False


def _verify_image(
    service: str, digest: str, tag: str, commit: str, work: Path, env: dict[str, str],
) -> None:
    description = f"{service} build provenance"
    data = _github(f"/attestations/{digest}", description, limit=_BUNDLE_LIMIT)
    entries = data.get("attestations")
    if not isinstance(entries, list) or not 1 <= len(entries) <= _MAX_BUNDLES:
        raise ReleaseVerificationError(f"Missing or excessive bundles for {description}")
    bundles = [_object(_object(entry).get("bundle")) for entry in entries]
    if not all(bundles):
        raise ReleaseVerificationError(f"Invalid bundle for {description}")
    bundle = work / f"{service}.jsonl"
    with bundle.open("w", encoding="utf-8") as stream:
        for item in bundles:
            stream.write(json.dumps(item, separators=(",", ":")) + "\n")

    image = _IMAGE_REPOS[service]
    ref = f"refs/tags/{tag}"
    raw = _command_output(
        [
            "/usr/bin/gh", "attestation", "verify", f"oci://{image}@{digest}",
            "--hostname", "github.com", "--repo", _REPO, "--bundle", str(bundle),
            "--cert-identity", f"{_WORKFLOW}@{ref}",
            "--cert-oidc-issuer", _OIDC_ISSUER,
            "--source-ref", ref, "--source-digest", commit, "--signer-digest", commit,
            "--deny-self-hosted-runners", "--predicate-type", _PROVENANCE, "--format", "json",
        ],
        work, env, timeout=50, limit=_VERIFICATION_LIMIT, description=description,
    )
    proofs = _json(raw, description)
    if not isinstance(proofs, list) or not any(_matching_proof(row, image, digest, ref, commit) for row in proofs):
        raise ReleaseVerificationError(f"Signed release identity mismatch for {description}")


def verify_release(version: str) -> tuple[dict[str, str], str]:
    """Return the two verified image references and the commit of the latest stable release."""
    if not isinstance(version, str):
        raise ReleaseVerificationError("Invalid requested release version")
    version = version.removeprefix("v")
    if not _VERSION.fullmatch(version):
        raise ReleaseVerificationError("Invalid requested release version")
    tag = f"v{version}"
    _validate_repository()
    release_id = _latest_release(tag)
    source = _tag_source(tag)
    with tempfile.TemporaryDirectory(prefix="acontrol-verifier-", dir="/tmp") as directory:
        work = Path(directory)
        env = _clean_environment(work)
        digests = {service: _image_digest(service, version, work, env) for service in _IMAGE_REPOS}
        for service, digest in digests.items():
            _verify_image(service, digest, tag, source[1], work, env)
        for service, digest in digests.items():
            if _image_digest(service, version, work, env) != digest:
                raise ReleaseVerificationError("Published image tag changed during verification")
    if _tag_source(tag) != source or _latest_release(tag) != release_id:
        raise ReleaseVerificationError("Published release changed during verification")
    images = {service: f"{_IMAGE_REPOS[service]}@{digest}" for service, digest in digests.items()}
    return images, source[1]


def download_source_file(commit_or_tag: str, path: str) -> bytes:
    """Read an allowlisted runtime config file for compatibility comparison."""
    if not isinstance(path, str) or path not in _SOURCE_FILES:
        raise ReleaseVerificationError("Unsupported runtime source file")
    if not isinstance(commit_or_tag, str) or not (
        _COMMIT.fullmatch(commit_or_tag)
        or (commit_or_tag.startswith("v") and _VERSION.fullmatch(commit_or_tag[1:]))
    ):
        raise ReleaseVerificationError("Invalid runtime source reference")
    return _fetch(f"{_RAW_REPO}/{commit_or_tag}/{path}", "runtime source file", {}, _SOURCE_LIMIT)
