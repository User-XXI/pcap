#!/usr/bin/env python3
"""
Задание 13 — анализ *исходящего* трафика с демонстрационным всплеском.
Первые 4 с     :  TCP-OUT → TCP-IN → UDP-OUT → UDP-IN   (по 100 пакетов/с)
Общая длительность: 20 с
"""

from __future__ import annotations
import os, sys, time, socket, struct, fcntl, platform, random, threading
from collections import defaultdict
from importlib import util as import_util
from pathlib import Path
from typing import Iterator, Tuple

import dpkt                       # разбор пакетов
import matplotlib.pyplot as plt   # график

# ---------------------------------------------------------------------------
#  Константы
# ---------------------------------------------------------------------------
DURATION          = 20            # сек, полный захват
START_DELAY       = 1             # пауза перед всплеском
DEBUG_DURATION    = 4             # сек, всплески
PKTS_PER_PHASE    = 100           # пакетов в фазе
TEST_REMOTE_IP    = "192.0.2.1"   # RFC 5737 (не маршрутизируется)
POST_CAPTURE      = 20            # секунд после окончания генератора
CAPTURE_TIME      = START_DELAY + DEBUG_DURATION + POST_CAPTURE   # = 25 с


PCAP_FILE_DEFAULT = Path("traffic.pcap")

UDP_PROTO, TCP_PROTO = 17, 6

# ---------------------------------------------------------------------------
#  ⬇⬇⬇  генератор контрольных пакетов на «чистых» сокетах  ⬇⬇⬇
# ---------------------------------------------------------------------------
def _csum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) >> 1), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ip_header(src: str, dst: str, proto: int, payload_len: int, ident: int) -> bytes:
    ver_ihl = 0x45
    tot_len = 20 + payload_len
    hdr = struct.pack("!BBHHHBBH4s4s",
                      ver_ihl, 0, tot_len, ident, 0, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    chk = _csum(hdr)
    return hdr[:10] + struct.pack("!H", chk) + hdr[12:]


def _udp_segment(sport: int, dport: int, data: bytes = b"x") -> bytes:
    length = 8 + len(data)
    return struct.pack("!HHHH", sport, dport, length, 0) + data      # чек-сумма 0 – ок


def _tcp_segment(sport: int, dport: int, syn: bool = True) -> bytes:
    seq = random.randint(0, 0xFFFFFFFF)
    flags = 0x02 if syn else 0x10                                    # SYN или ACK
    return struct.pack("!HHLLBBHHH",
                       sport, dport, seq, 0, 5 << 4, flags,
                       65535, 0, 0)                                  # чек-сумма 0


def _build_ip_packet(src: str, dst: str, segment: bytes, proto: int, ident: int) -> bytes:
    return _ip_header(src, dst, proto, len(segment), ident) + segment


def _burst(proto: str, direction: str, local_ip: str) -> None:
    """Фаза из 100 пакетов указанного направления/протокола."""
    dport = 80 if direction == "out" else 443
    sport_base = random.randint(20000, 60000)
    proto_num = TCP_PROTO if proto == "TCP" else UDP_PROTO
    pkts: list[bytes] = []

    for i in range(PKTS_PER_PHASE):
        sport = sport_base + i
        l4 = _tcp_segment(sport, dport) if proto == "TCP" else _udp_segment(sport, dport)
        pkt = _build_ip_packet(
            local_ip if direction == "out" else TEST_REMOTE_IP,
            TEST_REMOTE_IP if direction == "out" else local_ip,
            l4, proto_num, ident=random.randint(0, 65535)
        )
        pkts.append(pkt)

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        dst = TEST_REMOTE_IP if direction == "out" else local_ip
        for p in pkts:
            s.sendto(p, (dst, 0))


def start_debug_traffic(local_ip: str, start_delay: float = 1.0) -> None:
    phases = [("TCP", "out"), ("TCP", "in"), ("UDP", "out"), ("UDP", "in")]

    def _runner():
        time.sleep(start_delay)                 # ← 1-секундная пауза перед всплеском
        for idx, (proto, direction) in enumerate(phases):
            t0 = time.time()
            _burst(proto, direction, local_ip)
            if idx < len(phases) - 1:
                time.sleep(max(0, 1 - (time.time() - t0)))

    threading.Thread(target=_runner, daemon=True).start()

# ---------------------------------------------------------------------------
#  Утилиты
# ---------------------------------------------------------------------------
def inet_to_str(addr: bytes) -> str:
    return socket.inet_ntoa(addr)


def get_iface_and_ip() -> tuple[str, str]:
    """Первый не-loopback интерфейс с IPv4-адресом (Linux)."""
    if platform.system().lower() != "linux":
        raise RuntimeError("Скрипт рассчитан на Linux.")
    for iface in os.listdir("/sys/class/net/"):
        if iface == "lo":
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                ifreq = struct.pack("256s", iface.encode()[:15])
                ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, ifreq)[20:24])
                return iface, ip
        except OSError:
            continue
    raise RuntimeError("Не найден интерфейс с IP.")

# ---------------------------------------------------------------------------
#  Захват пакетов
# ---------------------------------------------------------------------------
pylibpcap = None
_spec = import_util.find_spec("pcap")
if _spec and _spec.origin and Path(_spec.origin).resolve() != Path(__file__).resolve():
    import importlib
    pylibpcap = importlib.import_module("pcap")          # type: ignore


def live_packets(iface: str, duration: int) -> Iterator[Tuple[float, bytes]]:
    if pylibpcap is None:
        sys.exit("Установите ‘pylibpcap’ и запустите с sudo.")
    pc = pylibpcap.pcap(name=iface, promisc=True, immediate=True, timeout_ms=50)
    stop_at = time.time() + duration

    for ts, raw in pc:               # итератор блокируется, но мы проверяем время сами
        yield ts, raw
        if time.time() >= stop_at:    # вышли за пределы ― прерываем захват
            break


# ---------------------------------------------------------------------------
#  Статистика
# ---------------------------------------------------------------------------
class CaptureStats:
    def __init__(self) -> None:
        self.outgoing, self.incoming = defaultdict(int), defaultdict(int)
        self.records: list[tuple[float, str]] = []
        self.start_ts: float | None = None

    def add(self, direction: str, proto: str, ts: float) -> None:
        if self.start_ts is None:
            self.start_ts = ts
        (self.outgoing if direction == "out" else self.incoming)[proto] += 1
        self.records.append((ts, proto))

    def report(self) -> None:
        print("\n===== ИТОГОВАЯ СТАТИСТИКА =====")
        print(f"Исходящие: {sum(self.outgoing.values()):>5}  {dict(self.outgoing)}")
        print(f"Входящие : {sum(self.incoming.values()):>5}  {dict(self.incoming)}")

        if len(self.records) < 2:
            print("Недостаточно пакетов для анализа.")
            return

        ts_sorted = sorted(ts for ts, _ in self.records)
        gaps = [b - a for a, b in zip(ts_sorted, ts_sorted[1:])]
        print("\nИнтервалы между соседними пакетами:")
        print(f"   средний : {sum(gaps)/len(gaps):.6f} с")
        print(f"   максимум: {max(gaps):.6f} с")
        print(f"   минимум : {min(gaps):.6f} с")

        base = int(self.start_ts)-1
        per_tcp, per_udp = defaultdict(int), defaultdict(int)
        for ts, proto in self.records:
            sec = int(ts) - base
            (per_tcp if proto == "TCP" else per_udp)[sec] += 1

        print("\nРаспределение (+offset → TCP/UDP):")
        for s in sorted(set(per_tcp) | set(per_udp)):
            print(f"  +{s:>2} с: {per_tcp.get(s,0):>4} TCP | {per_udp.get(s,0):>4} UDP")

        # ── график ──
        secs = sorted(set(per_tcp) | set(per_udp))
        plt.figure(figsize=(10, 4))
        plt.plot(secs, [per_tcp.get(s, 0) for s in secs],
                 label="TCP", marker="o", linewidth=1.3)
        plt.plot(secs, [per_udp.get(s, 0) for s in secs],
                 label="UDP", marker="o", linewidth=1.3)
        plt.title("Временное распределение исходящих IPv4-дейтаграмм")
        plt.xlabel("Секунды");  plt.ylabel("Пакеты")
        plt.grid(alpha=0.3);     plt.legend();  plt.tight_layout()
        plt.show()

# ---------------------------------------------------------------------------
#  Обработчик одного кадра
# ---------------------------------------------------------------------------
def handle_packet(ts: float, buf: bytes, stats: CaptureStats, local_ip: str) -> None:
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return
    if not isinstance(eth.data, dpkt.ip.IP):
        return

    ip = eth.data
    proto = "TCP" if isinstance(ip.data, dpkt.tcp.TCP) else \
            "UDP" if isinstance(ip.data, dpkt.udp.UDP) else None
    if proto is None:
        return

    src, dst = inet_to_str(ip.src), inet_to_str(ip.dst)
    if src == local_ip:                  # OUT
        stats.add("out", proto, ts)
        direction = "OUT"
    else:
        return

    print(f"[{time.strftime('%H:%M:%S', time.localtime(ts))}] {direction} {src} → {dst}")

# ---------------------------------------------------------------------------
#  main()
# ---------------------------------------------------------------------------
def main() -> None:
    print("===== TCP/UDP DATAGRAM ANALYZER — OUTGOING MODE =====\n")
    iface, local_ip = get_iface_and_ip()
    print(f"[INFO] iface={iface}, ip={local_ip}")

    # ── генератор контрольных пакетов ──
    start_debug_traffic(local_ip)
    print("[DEBUG] Контрольные пакеты будут отправлены в первые 4 с.\n")

    stats = CaptureStats()
    print(f"Захват исходящих пакетов на {iface} (⏱ {DURATION} с)…\n")
    for ts, buf in live_packets(iface, CAPTURE_TIME):
        handle_packet(ts, buf, stats, local_ip)
    stats.report()

if __name__ == "__main__":
    main()
