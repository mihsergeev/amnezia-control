"""Exercise image preparation without running Docker or using the network."""

import shutil
import subprocess

import pytest

from app.registry_pull import PULL_ERRORS, SHELL


PRIMARY = "registry.example/xray/core@sha256:" + "1" * 64
MIRROR = "mirror.example/xray/core@sha256:" + "1" * 64

MOCKS = r'''
set -euo pipefail
touch calls
timeout() {
    [ "$1" = --foreground ] || return 98
    printf 'timeout %s %s %s\n' "$2" "$3" "$4" >> calls
    shift 3
    "$@"
}
sudo() {
    case "$1 $2 $3" in
        'docker image inspect')
            printf 'inspect %s\n' "$4" >> calls
            [ "$4" = "${CACHED:-}" ]
            ;;
        'docker pull -q')
            local mode=$MIRROR_RESULT
            if [ "$4" = "$PRIMARY" ]; then
                if grep -Fxq -- "pull $PRIMARY" calls; then
                    mode=$PRIMARY_RETRY
                else
                    mode=$PRIMARY_FIRST
                fi
            elif grep -Fxq -- "pull $4" calls; then
                mode=$MIRROR_RETRY
            fi
            printf 'pull %s\n' "$4" >> calls
            case "$mode" in
                ok) printf 'verbose docker output\n'; return 0 ;;
                deadline) return 124 ;;
                dns) echo 'lookup registry.example on 192.0.2.8:53: i/o timeout' >&2; return 1 ;;
                nodata) echo 'lookup registry.example: no such host' >&2; return 1 ;;
                tls) echo 'https://registry.example/v2/?key=example-test x509: certificate signed by unknown authority' >&2; return 1 ;;
                route) echo 'connect: network is unreachable' >&2; return 1 ;;
                rate) echo '429 Too Many Requests' >&2; return 1 ;;
                integrity) echo 'manifest digest does not match pinned digest' >&2; return 1 ;;
                *) echo 'manifest unknown at registry.example' >&2; return 1 ;;
            esac
            ;;
        *) return 98 ;;
    esac
}
curl() {
    if [ "$#" -ne 16 ] || ! [ "$1" = -q ] || ! [ "$3" = --noproxy ] || ! [ "$4" = '*' ] \
        || ! [ "$5 $6" = '--proto =https' ] || ! [ "$7 $8 $9 ${10}" = '--connect-timeout 2 --max-time 3' ] \
        || ! [ "${11} ${12} ${13} ${14} ${15}" = '-s -o /dev/null -w %{http_code}' ]; then
        printf 'bad curl arguments\n' >> calls
        return 98
    fi
    printf 'curl %s %s\n' "$2" "${16}" >> calls
    case "$2" in
        -4) printf '%s' "$CURL4"; return "$CURL4_RC" ;;
        -6) printf '%s' "$CURL6"; return "$CURL6_RC" ;;
        *) return 98 ;;
    esac
}
'''


@pytest.fixture
def run(tmp_path, monkeypatch):
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is required for registry script tests")
    env = {
        "CACHED": "",
        "PRIMARY": PRIMARY,
        "PRIMARY_FIRST": "ok",
        "PRIMARY_RETRY": "ok",
        "MIRROR_RESULT": "ok",
        "MIRROR_RETRY": "ok",
        "CURL4": "401",
        "CURL4_RC": "0",
        "CURL6": "000",
        "CURL6_RC": "6",
    }

    def execute(command='ac_image_pull 40 20 15 "$PRIMARY"', **overrides):
        for key, value in (env | overrides).items():
            monkeypatch.setenv(key, value)
        result = subprocess.run(
            [bash, "--noprofile", "--norc", "-s"],
            input=f"{MOCKS}\n{SHELL}\n{command}\n".encode(),
            cwd=tmp_path, capture_output=True, timeout=12,
        )
        return (
            result.returncode,
            result.stdout.decode().strip(),
            result.stderr.decode().strip(),
            (tmp_path / "calls").read_text().splitlines(),
        )

    return execute


def test_cache_checks_all_candidates_before_network(run):
    status, output, errors, calls = run(
        f'ac_image_pull 40 20 15 "$PRIMARY" "{MIRROR}"', CACHED=MIRROR,
    )
    assert (status, output, errors) == (0, MIRROR, "")
    assert calls == [
        "timeout --kill-after=1s 5s sudo", f"inspect {PRIMARY}",
        "timeout --kill-after=1s 5s sudo", f"inspect {MIRROR}",
    ]


def test_primary_succeeds_without_a_second_attempt(run):
    status, output, errors, calls = run(PRIMARY_RETRY="unknown")
    assert (status, output, errors) == (0, PRIMARY, "")
    assert calls[-2:] == ["timeout --kill-after=3s 40s sudo", f"pull {PRIMARY}"]


@pytest.mark.parametrize("failure", ["dns", "tls", "integrity"])
def test_mirror_after_primary_error_retains_pinned_ref(run, failure):
    status, output, errors, calls = run(
        f'ac_image_pull 40 20 15 "$PRIMARY" "{MIRROR}"', PRIMARY_FIRST=failure,
    )
    assert (status, output, errors) == (0, MIRROR, "")
    assert calls[-4:] == [
        "timeout --kill-after=3s 40s sudo", f"pull {PRIMARY}",
        "timeout --kill-after=3s 20s sudo", f"pull {MIRROR}",
    ]


@pytest.mark.parametrize("initial_failure", ["dns", "deadline", "route", "rate"])
def test_retries_transient_primary_once_after_exhausting_mirrors(run, initial_failure):
    status, output, errors, calls = run(
        f'ac_image_pull 40 20 15 "$PRIMARY" "{MIRROR}"',
        PRIMARY_FIRST=initial_failure, MIRROR_RESULT="unknown",
    )
    assert (status, output, errors) == (0, PRIMARY, "")
    assert calls[-6:] == [
        "timeout --kill-after=3s 40s sudo", f"pull {PRIMARY}",
        "timeout --kill-after=3s 20s sudo", f"pull {MIRROR}",
        "timeout --kill-after=3s 15s sudo", f"pull {PRIMARY}",
    ]


def test_retries_transient_mirror_if_primary_error_is_permanent(run):
    status, output, errors, calls = run(
        f'ac_image_pull 40 20 15 "$PRIMARY" "{MIRROR}"', PRIMARY_FIRST="nodata", MIRROR_RESULT="rate",
    )
    assert (status, output, errors) == (0, MIRROR, "")
    assert calls[-6:] == [
        "timeout --kill-after=3s 40s sudo", f"pull {PRIMARY}",
        "timeout --kill-after=3s 20s sudo", f"pull {MIRROR}",
        "timeout --kill-after=3s 15s sudo", f"pull {MIRROR}",
    ]


@pytest.mark.parametrize("error,code,retry", [
    ("dns", 8, True),
    ("nodata", 8, False),
    ("deadline", 9, True),
    ("tls", 10, False),
    ("route", 11, True),
    ("unknown", 12, False),
    ("rate", 12, True),
    ("integrity", 13, False),
])
def test_failure_is_sanitized_and_https_check_never_counts_as_a_pull(run, error, code, retry):
    status, output, errors, calls = run(PRIMARY_FIRST=error, PRIMARY_RETRY=error)
    assert (status, output) == (code, "")
    assert calls.count(f"pull {PRIMARY}") == (2 if retry else 1)
    assert errors == "HTTPS реестра: IPv4 — HTTP 401, IPv6 — адрес не получен"
    assert "registry.example" not in errors and "192.0.2.8" not in errors and "example-test" not in errors
    assert {call for call in calls if call.startswith("curl ")} == {
        "curl -4 https://registry.example/v2/",
        "curl -6 https://registry.example/v2/",
    }
    assert calls.count("timeout --kill-after=1s 4s curl") == 2


def test_explicit_no_retry_and_tls_diagnostics(run):
    status, output, errors, calls = run(
        'ac_image_pull 40 0 0 "$PRIMARY"',
        PRIMARY_FIRST="dns", CURL4="http://registry.example/", CURL4_RC="60",
        CURL6="unexpected response",
    )
    assert (status, output) == (8, "")
    assert calls.count(f"pull {PRIMARY}") == 1
    assert errors == "HTTPS реестра: IPv4 — ошибка TLS, IPv6 — адрес не получен"


@pytest.mark.parametrize("failure,code", [("integrity", 13), ("tls", 10)])
def test_mirror_verification_error_is_visible_after_primary_dns_failure(run, failure, code):
    status, output, errors, _ = run(
        f'ac_image_pull 40 20 15 "$PRIMARY" "{MIRROR}"',
        PRIMARY_FIRST="dns", PRIMARY_RETRY="dns", MIRROR_RESULT=failure,
    )
    assert (status, output) == (code, "")
    assert errors.splitlines()[0] == f"Резервный реестр: {PULL_ERRORS[code]}"
    assert "mirror.example" not in errors


def test_docker_hub_maps_to_registry_v2_for_diagnostics(run):
    ref = "docker.io/library/alpine@sha256:" + "2" * 64
    status, _, _, calls = run('ac_image_pull 40 0 0 "$PRIMARY"', PRIMARY=ref, PRIMARY_FIRST="dns")
    assert status == 8
    assert {call for call in calls if call.startswith("curl ")} == {
        "curl -4 https://registry-1.docker.io/v2/",
        "curl -6 https://registry-1.docker.io/v2/",
    }


@pytest.mark.parametrize("code", [*PULL_ERRORS, 111])
def test_error_text_matches_python_api(run, code):
    status, output, errors, _ = run(f"ac_image_pull_error {code}")
    assert (status, output, errors) == (0, PULL_ERRORS.get(code, PULL_ERRORS[12]), "")
