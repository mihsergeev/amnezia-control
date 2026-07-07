#!/bin/bash
# Разворачивает AmneziaWG на ЧИСТОМ Ubuntu/Debian VPS. Проверено на Ubuntu 26.04
# (kernel 7.0.0) — использует userspace amneziawg-go, kernel-модуль не нужен.
#
# Требуется: образ amnezia-awg2 уже загружен в docker на этом хосте
#   (docker load -i amnezia-awg2.image.tar.gz) ИЛИ доступен в реестре.
# Запускать под пользователем с sudo. Идемпотентно.
set -e
IMG=amnezia-awg2
D=/opt/amnezia/awg
PORT="${1:-47180}"
SUBNET=10.8.1.0/24

echo "[1/7] docker"
command -v docker >/dev/null || curl -fsSL https://get.docker.com | sudo sh

echo "[2/7] tun + ip_forward (для userspace amneziawg-go и NAT)"
sudo modprobe tun || true
echo tun | sudo tee /etc/modules-load.d/tun.conf >/dev/null
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-acontrol-forward.conf >/dev/null
sudo sysctl -p /etc/sysctl.d/99-acontrol-forward.conf >/dev/null

echo "[3/7] генерация ключей и параметров обфускации"
# ВАЖНО: ENTRYPOINT образа = start.sh, поэтому awg вызываем через --entrypoint
PRIV=$(sudo docker run --rm --entrypoint awg $IMG genkey)
PUB=$(printf '%s' "$PRIV" | sudo docker run --rm -i --entrypoint awg $IMG pubkey)
PSK=$(sudo docker run --rm --entrypoint awg $IMG genpsk)
read Jc Jmin Jmax S1 S2 H1 H2 H3 H4 <<< "$(python3 - <<'PY'
import random
Jc = random.randint(3, 10)
Jmin = random.randint(4, 12)
Jmax = random.randint(Jmin + 50, Jmin + 900)
while True:
    S1, S2 = random.randint(15, 150), random.randint(15, 150)
    if S1 != S2 and S1 + 56 != S2 and S2 + 56 != S1:
        break
h = set()
while len(h) < 4:
    h.add(random.randint(5, 2**31 - 1))
H1, H2, H3, H4 = sorted(h)
print(f"{Jc} {Jmin} {Jmax} {S1} {S2} {H1} {H2} {H3} {H4}")
PY
)"

echo "[4/7] конфиг в $D (bind-mount, переживает пересоздание контейнера)"
sudo mkdir -p "$D"
printf '%s' "$PRIV" | sudo tee "$D/wireguard_server_private_key.key" >/dev/null
printf '%s' "$PUB"  | sudo tee "$D/wireguard_server_public_key.key" >/dev/null
printf '%s' "$PSK"  | sudo tee "$D/wireguard_psk.key" >/dev/null
printf '[]\n'       | sudo tee "$D/clientsTable" >/dev/null
sudo tee "$D/awg0.conf" >/dev/null <<CONF
[Interface]
PrivateKey = $PRIV
Address = $SUBNET
ListenPort = $PORT
Jc = $Jc
Jmin = $Jmin
Jmax = $Jmax
S1 = $S1
S2 = $S2
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4
CONF

echo "[5/7] запуск контейнера"
sudo docker rm -f $IMG >/dev/null 2>&1 || true
sudo docker run -d --name $IMG --restart always --privileged \
  --cap-add NET_ADMIN --cap-add SYS_MODULE \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -v "$D":/opt/amnezia/awg \
  -p "$PORT":"$PORT"/udp \
  $IMG >/dev/null
sleep 5

echo "[6/7] подъём awg0 + NAT (start.sh при загрузке не демонизирует amneziawg-go)"
BRINGUP='awg-quick down /opt/amnezia/awg/awg0.conf >/dev/null 2>&1; awg-quick up /opt/amnezia/awg/awg0.conf; iptables -t nat -C POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE; iptables -C FORWARD -i awg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i awg0 -j ACCEPT; iptables -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT'
sudo docker exec $IMG sh -c "$BRINGUP"

echo "[7/7] systemd-юнит для авто-подъёма после ребута"
sudo tee /etc/systemd/system/awg-up.service >/dev/null <<UNIT
[Unit]
Description=Bring up AmneziaWG interface + NAT inside container
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 8
ExecStart=/usr/bin/docker exec $IMG sh -c '$BRINGUP'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable awg-up.service >/dev/null 2>&1

echo "=== ГОТОВО ==="
echo "endpoint: $(curl -s ifconfig.me 2>/dev/null):$PORT"
echo "server_public_key: $PUB"
sudo docker exec $IMG wg show awg0 | grep -E "interface|listening"
