from pydantic import ValidationError
import pytest

from app.config import Settings


@pytest.mark.parametrize("repository", [
    "",
    "registry.example.test/cache/xray-core",
    "127.0.0.1:5000/cache/xray-core",
    "[2001:db8::4]:5443/cache/xray-core",
])
def test_mirror_repository_is_explicit_and_pinnable(repository):
    assert Settings(xray_registry_mirror=repository).xray_registry_mirror == repository


@pytest.mark.parametrize("repository", [
    "cache/xray-core",
    "https://registry.example.test/cache/xray-core",
    "registry.example.test/cache/xray-core:latest",
    "registry.example.test/cache/xray-core@sha256:aaaa",
    "registry.example.test:65536/cache/xray-core",
    "[2001:::4]:5443/cache/xray-core",
    "registry.example.test/cache//xray-core",
    "registry.example.test/cache/xray-core$(true)",
])
def test_mirror_repository_rejects_ambiguous_references(repository):
    with pytest.raises(ValidationError, match="expected a registry and repository"):
        Settings(xray_registry_mirror=repository)


def test_invalid_mirror_does_not_expose_credentials_in_error_message():
    with pytest.raises(ValidationError) as error:
        Settings(xray_registry_mirror="https://example-user:example-credential@registry.example.test/image")
    assert "example-credential" not in str(error.value)
