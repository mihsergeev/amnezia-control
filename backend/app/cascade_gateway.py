"""Keep the previous gateway recoverable until its replacement passes checks."""

import secrets
import shlex


_TRANSACTION = r'''
GW_BASE=@BASE@
GW_NAME=@NAME@
GW_OWNER=@OWNER@
GW_TX="$GW_BASE/gateway-transaction"
GW_LABEL=org.amnezia.control.install

gateway_id() {
  local rows
  rows=$(sudo docker container ls -a --no-trunc --format '{{.Names}} {{.ID}}') || return 1
  printf '%s\n' "$rows" | awk -v name="$GW_NAME" '$1 == name { print $2 }'
}

gateway_recover() {
  local token old running policy ids id current
  if ! sudo test -e "$GW_TX" && ! sudo test -L "$GW_TX"; then return 0; fi
  ! sudo test -L "$GW_TX" && [ "$(sudo stat -c '%u:%a' "$GW_TX")" = 0:700 ] || return 1
  if ! sudo test -f "$GW_TX/state"; then
    # No Docker or service changes are possible before publishing the state.
    sudo rm -rf "$GW_TX"
    return
  fi
  read -r token old running policy < <(sudo cat "$GW_TX/state") || return 1
  [[ "$token" =~ ^[0-9a-f]{32}$ ]] && [[ "$old" == - || "$old" =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ "$running" == true || "$running" == false ]] && [[ "$policy" =~ ^(no|always|unless-stopped|on-failure:[0-9]+)$ ]] || return 1
  if sudo test -f "$GW_TX/committed"; then
    if [ "$old" != - ]; then
      ids=$(sudo docker container ls -a --no-trunc --filter "id=$old" --format '{{.ID}}') || return 1
      if [ "$ids" = "$old" ]; then sudo docker rm "$old" >/dev/null || return 1; fi
    fi
  else
    if sudo test -f "$GW_TX/new-tproxy"; then
@TPROXY_PREPARE@
    fi
    if sudo test -f "$GW_TX/new-heal"; then
      sudo systemctl disable --now acontrol-cascade-heal.service >/dev/null || return 1
    fi
    if sudo test -f "$GW_TX/new-tproxy"; then
      sudo systemctl disable --now acontrol-cascade-tproxy.service >/dev/null || return 1
@TPROXY_DOWN@
    fi
    ids=$(sudo docker container ls -a --no-trunc --filter "label=$GW_LABEL=$token" --format '{{.ID}}') || return 1
    for id in $ids; do sudo docker rm -f "$id" >/dev/null || return 1; done
    if sudo test -f "$GW_TX/switch"; then
      if sudo test -f "$GW_TX/config.previous"; then
        sudo install -m 600 "$GW_TX/config.previous" "$GW_BASE/config/config.json.next" &&
          sudo mv -f "$GW_BASE/config/config.json.next" "$GW_BASE/config/config.json" || return 1
      else
        sudo rm -f "$GW_BASE/config/config.json" "$GW_BASE/config/config.json.next" || return 1
      fi
      if [ "$old" != - ]; then
        current=$(gateway_id) || return 1
        if [ "$current" != "$old" ]; then sudo docker rename "$old" "$GW_NAME" || return 1; fi
        sudo docker update --restart="$policy" "$old" >/dev/null || return 1
        if [ "$running" = true ]; then sudo docker start "$old" >/dev/null || return 1; fi
      fi
    fi
  fi
  sudo rm -rf "$GW_TX"
}

gateway_finish() {
  if ! gateway_recover; then
    echo "DEPLOY_ERROR: gateway rollback or cleanup is pending"
    return 1
  fi
}

gateway_abort() {
  local status=$1
  gateway_finish || status=1
  if [ "$status" -ne 0 ]; then
    echo "DEPLOY_ERROR: ${GW_ERROR:-gateway operation interrupted}"
    exit "$status"
  fi
}

gateway_begin() {
  local mount owner running policy count
  GW_OLD=$(gateway_id) || fail 'gateway lookup'
  running=false
  policy=no
  if [ -n "$GW_OLD" ]; then
    mount=$(sudo docker container inspect -f '{{range .Mounts}}{{if eq .Destination "/usr/local/etc/xray"}}{{.Source}}{{end}}{{end}}' "$GW_OLD") || fail 'gateway lookup'
    case "$mount" in "$GW_BASE/config"|"$GW_BASE/boot") ;; *) fail 'gateway ownership';; esac
    if [ -n "$GW_OWNER" ]; then
      owner=$(sudo docker container inspect -f '{{index .Config.Labels "org.amnezia.control.owner"}}' "$GW_OLD") || fail 'gateway lookup'
      [ "$owner" = "$GW_OWNER" ] || fail 'gateway ownership'
    fi
    read -r running policy count < <(sudo docker container inspect -f '{{.State.Running}} {{.HostConfig.RestartPolicy.Name}} {{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$GW_OLD") || fail 'gateway lookup'
    [ "$policy" != on-failure ] || policy="$policy:$count"
    # Docker can store the default restart policy as an empty string.
    if [[ "$policy" =~ ^[0-9]+$ ]]; then policy=no; fi
  fi
  sudo mkdir -m 700 "$GW_TX" || fail 'gateway transaction directory'
  printf '%s %s %s %s\n' "$GW_TOKEN" "${GW_OLD:--}" "$running" "$policy" | sudo tee "$GW_TX/state.next" >/dev/null || fail 'gateway transaction state'
  sudo mv -f "$GW_TX/state.next" "$GW_TX/state" || fail 'gateway transaction state'
  trap 'gateway_abort "$?"' EXIT
  trap 'exit 1' HUP INT TERM
  # Deploy status must not report failure until the rollback attempt has ended.
  fail() { GW_ERROR=$1; exit 1; }
}

gateway_switch() {
  if sudo test -f "$GW_BASE/config/config.json"; then
    sudo install -m 600 "$GW_BASE/config/config.json" "$GW_TX/config.previous" || fail 'gateway config backup'
  fi
  sudo touch "$GW_TX/switch" || fail 'gateway transaction state'
  if [ -n "$GW_OLD" ]; then
    sudo docker update --restart=no "$GW_OLD" >/dev/null || fail 'gateway restart policy'
    sudo docker stop -t 5 "$GW_OLD" >/dev/null || fail 'stop previous gateway'
  fi
  sudo install -m 600 "$GW_TX/config/config.json" "$GW_BASE/config/config.json.next" &&
    sudo mv -f "$GW_BASE/config/config.json.next" "$GW_BASE/config/config.json" || fail 'activate gateway config'
  sudo docker start "$GW_NEXT" >/dev/null || fail 'start new gateway'
}

gateway_commit() {
  if [ -n "$GW_OLD" ]; then
    sudo docker rename "$GW_OLD" "$GW_NAME-previous-$GW_TOKEN" || fail 'rename previous gateway'
  fi
  sudo docker rename "$GW_NEXT" "$GW_NAME" || fail 'promote new gateway'
}
'''


def commands(base: str, name: str, owner: str, tproxy_down: str, *, tproxy_prepare: str = ":") -> str:
    return (
        _TRANSACTION.replace("@BASE@", shlex.quote(base))
        .replace("@NAME@", shlex.quote(name))
        .replace("@OWNER@", shlex.quote(owner))
        .replace("@TPROXY_PREPARE@", tproxy_prepare.replace("exit 73", "return 1"))
        .replace("@TPROXY_DOWN@", tproxy_down.replace("exit 73", "return 1"))
        + f"\nGW_TOKEN={secrets.token_hex(16)}\n"
    )
