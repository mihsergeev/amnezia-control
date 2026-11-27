"""Загрузка образов и сборка AmneziaWG 3.x, в том числе на старом Docker.

Профиль seccomp старого Docker отвечает EPERM на незнакомые ему системные
вызовы, а musl в Alpine 3.14+ откатывается с faccessat2 только по ENOSYS. В
итоге make внутри docker build падал с "/bin/sh: Operation not permitted"
(Ubuntu 20.04: Docker 19.03, а также 20.10.1 с runc 1.0.0-rc92). На таком
Docker бинари компилируются в docker run без seccomp, а образ собирается
поверх готовых.
"""

import os
import re
import shutil
import subprocess

import pytest

from app import cascade, cascade_awg, cascade_probe, deploy


FAKE_DOCKER = r'''
TEST_DIR=$PWD
BUILD="$TEST_DIR/build"
IMG=awg-test
CONT=awg-existing
BUILDER=probe-builder-test
BUILDER_LABEL=org.amnezia.control.probe-builder=$BUILDER
log() { printf '%s\n' "$*"; }

sudo() {
    case "$1" in
        docker) shift; docker "$@" ;;
        mkdir|tee) "$@" ;;
        rm) [ "$#" -eq 3 ] && [ "$2" = -rf ] && [ "$3" = "$BUILD/bin" ] ;;
        *) return 98 ;;
    esac
}

record() { printf '%s\n' "$*" >> "$TEST_DIR/calls"; }
local_image() { grep -Fxq -- "$1" "$TEST_DIR/images"; }

timeout() {
    [ "$1" = --foreground ] || return 98
    if [ "$6" = pull ]; then record timeout "$@"; fi
    shift 3
    case "$1" in
        sudo|curl) TEST_ECR_DEADLINE=1 "$@" ;;
        *) return 98 ;;
    esac
}

curl() { printf 401; }

apk() {
    record apk "$@"
    [ "$TEST_FAULT" != apk ]
}

make() {
    record make
    case "$TEST_FAULT" in
        seccomp) echo 'make: /bin/sh: Operation not permitted' >&2; return 2 ;;
        make) echo 'make: *** Error 1' >&2; return 2 ;;
    esac
}

docker() {
    local image script
    case "$1" in
        image) [ "$2" = inspect ] && record inspect "$3" && local_image "$3" ;;
        inspect) record inspect-container "${@: -1}"; echo sha256:old-image ;;
        tag) record "$@" ;;
        pull)
            [ "$2" != -q ] || set -- pull "$3"
            record "$@"
            if [ "${TEST_ECR_DEADLINE:-0}" = 1 ] && grep -Fxq -- "$2" <<< "$TEST_ECR_TIMED_OUT"; then
                return 124
            fi
            if grep -Fxq -- "$2" <<< "$TEST_REGISTRY_DOWN"; then
                echo 'failed to fetch anonymous token: dial tcp [2001:db8::1]:443: connect: network is unreachable' >&2
                return 1
            fi
            printf '%s\n' "$2" >> "$TEST_DIR/images"
            ;;
        run)
            image=${@: -4:1}
            script=${@: -1}
            record "${*:1:$#-3}"
            local_image "$image" || return 98
            case "$*" in
                *seccomp=unconfined*)
                    case "$script" in
                        *'/src/amneziawg-go /res/'*) printf binary > "$BUILD/bin/amneziawg-go" ;;
                        *'/out/usr/bin/awg /out/usr/bin/awg-quick /res/'*)
                            printf binary > "$BUILD/bin/awg"
                            printf binary > "$BUILD/bin/awg-quick"
                            ;;
                        *) return 98 ;;
                    esac
                    ;;
                *)
                    [ "$TEST_FAULT" != daemon ] || return 125
                    # Выполняем код проверки из Docker run со своими apk и make.
                    script=${script//\/tmp\/m/\$TEST_DIR\/makefile}
                    (eval "$script")
                    ;;
            esac
            ;;
        version) echo 19.03.14 ;;
        build)
            record "$@"
            while [ "$#" -gt 1 ]; do
                if [ "$1" = --build-arg ]; then
                    local_image "${2#*=}" || return 98
                    shift
                fi
                shift
            done
            ;;
        *) record "unexpected docker command $*"; return 98 ;;
    esac
}
'''


@pytest.fixture
def run_build(tmp_path):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("нужен bash")

    def run(*, context="deploy", down=(), timed_out=(), cached=(), fault="", cached_binaries=False):
        build = tmp_path / "build"
        build.mkdir()
        if cached_binaries:
            (build / "bin").mkdir()
            (build / "bin/.tags").write_bytes(
                f"go={deploy.AWG3_GO_TAG} tools={deploy.AWG3_TOOLS_TAG}\n".encode(),
            )
            for binary in ("awg", "awg-quick", "amneziawg-go"):
                (build / "bin" / binary).write_bytes(b"cached binary")
        (tmp_path / "images").write_bytes("".join(f"{image}\n" for image in cached).encode())

        if context == "probe":
            script = cascade_probe._prepare_config("awg", [cascade_awg.IMAGE], "")["build_script"]
        else:
            shell_mode = "set -e" if context == "deploy" else "set +e"
            script = "\n".join([shell_mode, *deploy._v3_build_lines(3)])
        result = subprocess.run(
            [bash, "-s"], input=f"{FAKE_DOCKER}\n{script}\n".encode(), cwd=tmp_path,
            env=dict(
                os.environ, TEST_REGISTRY_DOWN="\n".join(down), TEST_ECR_TIMED_OUT="\n".join(timed_out),
                TEST_FAULT=fault,
            ),
            capture_output=True, timeout=20,
        )
        return result, (tmp_path / "calls").read_text(encoding="utf-8").splitlines()

    return run


@pytest.mark.parametrize("repository,hub,ecr,mirror", [
    ("alpine", deploy._V3_TOOLS_IMAGE, deploy._V3_TOOLS_IMAGE_IPV4, deploy._V3_TOOLS_IMAGE_MIRROR),
    ("golang", deploy._V3_GO_IMAGE, deploy._V3_GO_IMAGE_IPV4, deploy._V3_GO_IMAGE_MIRROR),
])
def test_official_images_have_equal_pins(repository, hub, ecr, mirror):
    hub_repo, hub_digest = hub.split("@")
    ecr_repo, ecr_digest = ecr.split("@")
    mirror_repo, mirror_digest = mirror.split("@")
    assert hub_repo == f"docker.io/library/{repository}"
    assert ecr_repo == f"public.ecr.aws/docker/library/{repository}"
    assert mirror_repo == f"mirror.gcr.io/library/{repository}"
    assert hub_digest == ecr_digest == mirror_digest
    assert re.fullmatch("sha256:[a-f0-9]{64}", hub_digest)


@pytest.mark.parametrize("context", ["deploy", "probe"])
@pytest.mark.parametrize("failed", [None, "alpine", "go", "both"])
def test_cold_build_uses_selected_pinned_images(run_build, context, failed):
    alpine = deploy._V3_TOOLS_IMAGE
    go = deploy._V3_GO_IMAGE
    down = [image for role, image in (("alpine", alpine), ("go", go)) if failed in (role, "both")]
    result, calls = run_build(context=context, down=down)
    assert result.returncode == 0, result.stderr.decode()

    picked_alpine = deploy._V3_TOOLS_IMAGE_IPV4 if alpine in down else alpine
    picked_go = deploy._V3_GO_IMAGE_IPV4 if go in down else go
    expected = [alpine] + ([picked_alpine] if alpine in down else [])
    expected += [go] + ([picked_go] if go in down else [])
    assert [line.removeprefix("pull ") for line in calls if line.startswith("pull ")] == expected
    runs = [line for line in calls if line.startswith("run ")]
    assert len(runs) == 1 and runs[0].endswith(picked_alpine)
    assert "seccomp=unconfined" not in runs[0]
    builds = [line for line in calls if line.startswith("build ")]
    assert len(builds) == 1
    assert f"--build-arg AWG_GO_IMAGE={picked_go}" in builds[0]
    assert f"--build-arg AWG_ALPINE_IMAGE={picked_alpine}" in builds[0]
    assert "--pull" not in builds[0]
    if context == "probe":
        assert "--name probe-builder-test --label org.amnezia.control.probe-builder=probe-builder-test" in runs[0]
        assert "--force-rm" in builds[0] and f"-t {cascade_probe.AWG_PROBE_IMAGE}" in builds[0]
        assert not any(line.startswith(("inspect-container ", "tag ")) for line in calls)
    else:
        assert "inspect-container awg-existing" in calls
        assert "tag sha256:old-image awg-test:prev" in calls


@pytest.mark.parametrize("context", ["deploy", "probe"])
def test_ecr_timeout_uses_google_cache(run_build, context):
    hub = deploy._V3_GO_IMAGE
    ecr = deploy._V3_GO_IMAGE_IPV4
    mirror = deploy._V3_GO_IMAGE_MIRROR
    result, calls = run_build(context=context, down=(hub,), timed_out=(ecr,))
    assert result.returncode == 0, result.stderr.decode()
    pulls = [line for line in calls if line.startswith("pull ")]
    assert pulls == [
        f"pull {deploy._V3_TOOLS_IMAGE}", f"pull {hub}", f"pull {ecr}", f"pull {mirror}",
    ]
    assert f"timeout --foreground --kill-after=3s 45s sudo docker pull -q {ecr}" in calls
    builds = [line for line in calls if line.startswith("build ")]
    assert len(builds) == 1 and f"--build-arg AWG_GO_IMAGE={mirror}" in builds[0]
    assert not any("seccomp=unconfined" in line for line in calls)


def test_cached_google_images_are_used_without_pulling(run_build):
    go = deploy._V3_GO_IMAGE_MIRROR
    alpine = deploy._V3_TOOLS_IMAGE_MIRROR
    result, calls = run_build(cached=(go, alpine))
    assert result.returncode == 0, result.stderr.decode()
    assert not any(line.startswith(("pull ", "timeout ")) for line in calls)
    builds = [line for line in calls if line.startswith("build ")]
    assert len(builds) == 1
    assert f"--build-arg AWG_GO_IMAGE={go}" in builds[0]
    assert f"--build-arg AWG_ALPINE_IMAGE={alpine}" in builds[0]


@pytest.mark.parametrize("context", ["cascade", "probe"])
@pytest.mark.parametrize("missing", ["Alpine", "Go"])
def test_all_registries_down_report_missing_image(run_build, context, missing):
    if missing == "Alpine":
        down = (deploy._V3_TOOLS_IMAGE, deploy._V3_TOOLS_IMAGE_IPV4, deploy._V3_TOOLS_IMAGE_MIRROR)
    else:
        down = (deploy._V3_GO_IMAGE, deploy._V3_GO_IMAGE_IPV4, deploy._V3_GO_IMAGE_MIRROR)
    result, calls = run_build(context=context, down=down)
    output = result.stderr.decode()
    assert result.returncode != 0
    assert f"DEPLOY_ERROR: не удалось загрузить {missing}" in output
    assert "Docker Hub, Amazon ECR Public (IPv4) или mirror.gcr.io" in output
    pulls = [line.removeprefix("pull ") for line in calls if line.startswith("pull ")]
    expected = down if context == "probe" else (*down, down[0])
    assert tuple(pulls[-len(expected):]) == expected
    assert not any(line.startswith("build ") or "seccomp=unconfined" in line for line in calls)
    if missing == "Alpine":
        assert not any(line.startswith("run ") for line in calls)


@pytest.mark.parametrize("fault,message", [
    ("apk", "apk не смог установить make"),
    ("make", "не прошла проверка make"),
    ("daemon", "Docker не смог запустить проверку seccomp"),
])
def test_unrelated_seccomp_probe_failure_does_not_compile_unconfined(run_build, fault, message):
    result, calls = run_build(fault=fault)
    assert result.returncode != 0 and f"DEPLOY_ERROR: {message}" in result.stderr.decode()
    assert not any(line.startswith("build ") or "seccomp=unconfined" in line for line in calls)
    assert ("make" in calls) == (fault == "make")


@pytest.mark.parametrize("context,cached_binaries", [("deploy", False), ("probe", False), ("deploy", True)])
def test_old_seccomp_compiles_only_missing_binaries(run_build, context, cached_binaries, tmp_path):
    alpine = deploy._V3_TOOLS_IMAGE_IPV4
    go = deploy._V3_GO_IMAGE_IPV4
    result, calls = run_build(
        context=context, fault="seccomp", cached_binaries=cached_binaries,
        cached=(alpine,), down=(deploy._V3_GO_IMAGE, go) if cached_binaries else (deploy._V3_GO_IMAGE,),
    )
    assert result.returncode == 0, result.stderr.decode()
    builds = [line for line in calls if line.startswith("build ")]
    assert len(builds) == 1 and "--force-rm" in builds[0] and "Dockerfile.prebuilt" in builds[0]
    assert f"--build-arg AWG_ALPINE_IMAGE={alpine}" in builds[0]
    assert "AWG_GO_IMAGE=" not in builds[0] and "--platform" not in builds[0]
    unconfined = [line for line in calls if "--security-opt seccomp=unconfined" in line]
    assert [line.removeprefix("pull ") for line in calls if line.startswith("pull ")] == (
        [] if cached_binaries else [deploy._V3_GO_IMAGE, go]
    )
    if cached_binaries:
        assert not unconfined and f"inspect {deploy._V3_GO_IMAGE}" not in calls
        assert (tmp_path / "build/bin/awg").read_bytes() == b"cached binary"
    else:
        assert len(unconfined) == 2
        assert unconfined[0].endswith(go) and unconfined[1].endswith(alpine)
        assert (tmp_path / "build/bin/.tags").read_text().strip() == (
            f"go={deploy.AWG3_GO_TAG} tools={deploy.AWG3_TOOLS_TAG}"
        )
        if context == "probe":
            assert all("--name probe-builder-test --label org.amnezia.control.probe-builder=probe-builder-test"
                       in line for line in unconfined)


def test_installer_scripts_include_shared_build():
    awg3 = deploy.generate_server_config_v3(47300)
    for mode in ("deploy", "update"):
        assert "\n".join(deploy._v3_build_lines(5)) in deploy.build_script_v3(mode, 47300, awg3)
    assert "\n".join(deploy._v3_build_lines(3)) in deploy.build_script_upgrade31(awg3["conf"])
    params = cascade_awg.new_params() | {
        "entry_ip": "192.0.2.10", "exit_ip": "198.51.100.20", "entry_port": 51830, "exit_port": 51831,
    }
    cascade_build = "\n".join([
        f"if ! sudo docker image inspect {cascade_awg.IMAGE} >/dev/null 2>&1; then",
        *("  " + line for line in deploy._v3_build_lines(8)),
        "fi",
    ])
    assert cascade_build in cascade.build_entry_script("awg", params["exit_ip"], 3, params)
    assert cascade_build in cascade.build_exit_script("awg", params["entry_ip"], 3, params)


def test_prebuilt_image_matches_regular_final_stage() -> None:
    # финальный образ одинаковый на любом Docker, отличается только источник бинарей
    regular = deploy._dockerfile_v3()
    final = regular[regular.rindex("FROM "):]
    prebuilt = deploy._dockerfile_v3_prebuilt()
    assert regular.startswith(
        f"ARG AWG_GO_IMAGE={deploy._V3_GO_IMAGE}\n"
        f"ARG AWG_ALPINE_IMAGE={deploy._V3_TOOLS_IMAGE}\n"
        "FROM ${AWG_GO_IMAGE} AS go-build\n"
    )
    assert "FROM ${AWG_ALPINE_IMAGE} AS tools-build\n" in regular
    assert final.startswith("FROM ${AWG_ALPINE_IMAGE}\n")
    src = re.compile(r"^COPY .+ (/usr/bin/\S+)$", re.M)
    assert src.sub(r"COPY X \1", prebuilt[prebuilt.index("FROM "):]) == src.sub(r"COPY X \1", final)
    assert prebuilt.startswith(f"ARG AWG_ALPINE_IMAGE={deploy._V3_TOOLS_IMAGE}\n")
    assert "golang" not in prebuilt and "make" not in prebuilt
    for name in ("amneziawg-go", "awg", "awg-quick"):
        assert f"COPY bin/{name} /usr/bin/{name}" in prebuilt
