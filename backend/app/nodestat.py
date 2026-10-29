"""Чтение ресурсов ноды (CPU/RAM/диск/аптайм) одной SSH-командой."""

from dataclasses import dataclass

import asyncssh

# Одна команда, вывод — строки KEY=VALUE (устойчиво к разным дистрибутивам).
_CMD = (
    'echo "CPU=$(nproc 2>/dev/null || echo 0)"; '
    'echo "LOAD=$(cut -d\' \' -f1 /proc/loadavg 2>/dev/null || echo 0)"; '
    "awk '/^MemTotal:/{t=$2}/^MemAvailable:/{a=$2}"
    'END{printf "MEMTOTAL=%d\\nMEMAVAIL=%d\\n", t*1024, a*1024}\' '
    "/proc/meminfo 2>/dev/null; "
    "df -B1 -P / 2>/dev/null | tail -1 | "
    'awk \'{print "DISKTOTAL="$2"\\nDISKUSED="$3}\'; '
    'echo "UPTIME=$(cut -d\' \' -f1 /proc/uptime 2>/dev/null || echo 0)"; '
    # счетчики CPU с загрузки (тики): занято = user nice system irq softirq steal,
    # всего = занято + idle + iowait. Процент считает коллектор по разнице с
    # прошлым снимком, а не по load average: load на 1 vCPU легко выше 1 из-за
    # ожидания IO при свободном процессоре
    "awk '/^cpu /{b=$2+$3+$4+$7+$8+$9; "
    'printf "CPUBUSY=%.0f\\nCPUTOTAL=%.0f\\n", b, b+$5+$6}\' /proc/stat 2>/dev/null; '
    # PSI: доля времени, когда готовым задачам не хватало CPU (ядра 4.20+)
    "awk '/^some/{for(i=2;i<=NF;i++) if($i ~ /^avg60=/){sub(/avg60=/,\"\",$i); "
    'print "PSICPU="$i}}\' /proc/pressure/cpu 2>/dev/null'
)


@dataclass
class NodeResources:
    cpu_count: int
    load1: float
    mem_total: int
    mem_used: int
    disk_total: int
    disk_used: int
    uptime_seconds: int
    cpu_busy: int = 0
    cpu_total: int = 0
    # None - ядро без PSI
    psi_cpu: float | None = None


def _parse(text: str) -> NodeResources:
    kv: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            kv[k.strip()] = v.strip()

    def i(key: str) -> int:
        try:
            return int(float(kv.get(key, "0")))
        except (ValueError, TypeError):
            return 0

    def f(key: str) -> float:
        try:
            return float(kv.get(key, "0"))
        except (ValueError, TypeError):
            return 0.0

    mem_total = i("MEMTOTAL")
    mem_avail = i("MEMAVAIL")
    mem_used = max(0, mem_total - mem_avail) if mem_total else 0
    return NodeResources(
        cpu_count=i("CPU"),
        load1=f("LOAD"),
        mem_total=mem_total,
        mem_used=mem_used,
        disk_total=i("DISKTOTAL"),
        disk_used=i("DISKUSED"),
        uptime_seconds=i("UPTIME"),
        cpu_busy=i("CPUBUSY"),
        cpu_total=i("CPUTOTAL"),
        psi_cpu=f("PSICPU") if "PSICPU" in kv else None,
    )


async def read_resources(conn: asyncssh.SSHClientConnection) -> NodeResources:
    result = await conn.run(_CMD, check=False)
    return _parse(result.stdout or "")
