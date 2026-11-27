"""Shell helpers shared by node-side Docker image preparation scripts."""

import shlex


PULL_ERRORS = {
    8: "Ошибка DNS при загрузке образа Docker",
    9: "Истекло время загрузки образа Docker",
    10: "Ошибка проверки TLS при загрузке образа Docker",
    11: "Ошибка сетевого подключения при загрузке образа Docker",
    12: "Не удалось загрузить образ Docker из доступных реестров",
    13: "Digest загруженного образа Docker не совпадает с ожидаемым",
}

CACHE_SHELL = r'''
ac_image_cached() {
    local ref
    for ref in "$@"; do
        if timeout --foreground --kill-after=1s 5s sudo docker image inspect "$ref" >/dev/null 2>&1; then
            printf '%s\n' "$ref"
            return 0
        fi
    done
    return 1
}
'''.strip()

_PULL_SHELL = r'''
# Scope output to a selected image; Docker error text may contain private URLs.
ac_image_pull_attempt() {
    local seconds=$1 ref=$2 output status
    if output=$(
        set -o pipefail
        LC_ALL=C timeout --foreground --kill-after=3s "${seconds}s" sudo docker pull -q "$ref" 2>&1 >/dev/null |
            tail -c 8192
    ); then
        return 0
    else
        status=$?
    fi
    output=${output,,}
    if [ "$status" = 124 ] || [ "$status" = 137 ]; then
        return 9
    fi
    case "$output" in
        *"digest mismatch"*|*"unexpected digest"*|*"digest "*"does not match"*|*"failed to verify checksum"*|*"unexpected commit digest"*) return 13 ;;
        *"x509:"*|*"tls: "*|*"certificate verify failed"*|*"certificate signed by unknown authority"*) return 10 ;;
        *"no such host"*|*"name or service not known"*) return 14 ;;
        *"lookup "*|*"temporary failure in name resolution"*|*"server misbehaving"*|*"could not resolve host"*) return 8 ;;
        *"timed out"*|*"timeout"*|*"deadline exceeded"*) return 9 ;;
        *"network is unreachable"*|*"no route to host"*|*"connection refused"*|*"connection reset"*|*"unexpected eof"*) return 11 ;;
        *"too many requests"*|*"toomanyrequests"*|*"429 too many"*|*"500 internal server error"*|*"502 bad gateway"*|*"503 service unavailable"*|*"504 gateway timeout"*) return 15 ;;
        *) return 12 ;;
    esac
}

ac_image_https_probe() {
    local family=$1 host=$2 http status
    if http=$(timeout --foreground --kill-after=1s 4s curl -q "$family" --noproxy '*' \
        --proto '=https' --connect-timeout 2 --max-time 3 -s -o /dev/null \
        -w '%{http_code}' "https://$host/v2/" 2>/dev/null); then
        if [[ "$http" =~ ^[1-5][0-9][0-9]$ ]]; then
            printf 'HTTP %s\n' "$http"
        else
            printf 'нет ответа\n'
        fi
    else
        status=$?
        case "$status" in
            6) printf 'адрес не получен\n' ;;
            28|124|137) printf 'таймаут\n' ;;
            35|51|60|77) printf 'ошибка TLS\n' ;;
            *) printf 'нет подключения\n' ;;
        esac
    fi
}

ac_image_diagnose() {
    local host=${1%%/*} ipv4 ipv6 v4fd v6fd
    case "$host" in
        docker.io|index.docker.io) host=registry-1.docker.io ;;
    esac
    [[ "$host" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?$ ]] || return 0
    command -v curl >/dev/null 2>&1 || return 0
    # Shell-side HTTPS checks use the current resolver and verify TLS. They
    # cannot prove that dockerd can authenticate or fetch image layers.
    exec {v4fd}< <(ac_image_https_probe -4 "$host")
    exec {v6fd}< <(ac_image_https_probe -6 "$host")
    IFS= read -r ipv4 <&"$v4fd" || ipv4='нет результата'
    IFS= read -r ipv6 <&"$v6fd" || ipv6='нет результата'
    exec {v4fd}<&- {v6fd}<&-
    printf 'HTTPS реестра: IPv4 — %s, IPv6 — %s\n' "$ipv4" "$ipv6" >&2
}

ac_image_retryable() {
    case "$1" in 8|9|11|15) return 0 ;; *) return 1 ;; esac
}

ac_image_pull() {
    [[ $# -ge 4 && $1 =~ ^[1-9][0-9]*$ && $2 =~ ^[0-9]+$ && $3 =~ ^[0-9]+$ ]] || return 12
    local primary_seconds=$1 fallback_seconds=$2 retry_seconds=$3
    shift 3
    local primary=$1 ref status retry_ref='' fallback_status=0 fallback_error
    if ac_image_cached "$@"; then
        return 0
    fi
    if ac_image_pull_attempt "$primary_seconds" "$primary"; then
        printf '%s\n' "$primary"
        return 0
    else
        status=$?
    fi
    if ac_image_retryable "$status"; then retry_ref=$primary; fi
    shift
    if [ "$fallback_seconds" -gt 0 ]; then
        for ref in "$@"; do
            if ac_image_pull_attempt "$fallback_seconds" "$ref"; then
                printf '%s\n' "$ref"
                return 0
            else
                fallback_error=$?
            fi
            if [ "$fallback_error" = 13 ]; then
                fallback_status=13
            elif [ "$fallback_error" = 10 ] && [ "$fallback_status" != 13 ]; then
                fallback_status=10
            elif [ -z "$retry_ref" ] && ac_image_retryable "$fallback_error"; then
                retry_ref=$ref
            fi
        done
    fi
    if [ "$retry_seconds" -gt 0 ] && [ -n "$retry_ref" ]; then
        if ac_image_pull_attempt "$retry_seconds" "$retry_ref"; then
            printf '%s\n' "$retry_ref"
            return 0
        else
            fallback_error=$?
        fi
        if [ "$retry_ref" = "$primary" ]; then
            status=$fallback_error
        elif [ "$fallback_error" = 13 ] || { [ "$fallback_error" = 10 ] && [ "$fallback_status" != 13 ]; }; then
            fallback_status=$fallback_error
        fi
    fi
    case "$status" in
        14) status=8 ;;
        15) status=12 ;;
    esac
    if [ "$fallback_status" = 13 ] || { [ "$fallback_status" = 10 ] && [ "$status" != 13 ]; }; then
        printf 'Резервный реестр: %s\n' "$(ac_image_pull_error "$fallback_status")" >&2
        status=$fallback_status
    fi
    ac_image_diagnose "$primary"
    return "$status"
}
'''.strip()

_ERROR_CASES = "\n".join(
    f"        {code}) printf '%s\\n' {shlex.quote(message)} ;;"
    for code, message in PULL_ERRORS.items()
)
_ERROR_SHELL = (
    "ac_image_pull_error() {\n"
    '    case "${1:-}" in\n'
    f"{_ERROR_CASES}\n"
    f"        *) printf '%s\\n' {shlex.quote(PULL_ERRORS[12])} ;;\n"
    "    esac\n"
    "}"
)

SHELL = "\n\n".join((CACHE_SHELL, _PULL_SHELL, _ERROR_SHELL))
