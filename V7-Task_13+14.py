#!/usr/bin/env python3
"""
Задание 13
-----------
1) Анализ **исходящего** TCP / UDP-трафика  
2) Работаем с **live-трафиком**, а не с pcap-файлом  
3) Длительность захвата — 20 с  
4) Автовыбор активного интерфейса (Linux) *или* ручное «eth0»  
5) IP-адрес определяется автоматически  

Запуск без root поддерживается, если у бинарника Python есть capability  
`cap_net_raw,cap_net_admin=eip` (см. man setcap). Иначе требуется sudo.
"""
from __future__ import annotations

import os
import socket
import struct
import fcntl
import sys
import time
import platform
from collections import defaultdict
from importlib import util as import_util
from pathlib import Path
from typing import Iterator, Tuple

import dpkt                       # разбор Ethernet/IP/TCP/UDP/pcap
import matplotlib.pyplot as plt

# ————————————————————————————————————————————————————————————————
#  Безопасный импорт pylibpcap (может называться просто «pcap»)
# ————————————————————————————————————————————————————————————————
pylibpcap = None
_spec = import_util.find_spec("pcap")
if _spec and _spec.origin and Path(_spec.origin).resolve() != Path(__file__).resolve():
    import importlib

    pylibpcap = importlib.import_module("pcap")          # type: ignore

# ————————————————————————————————————————————————————————————————
#  Константы
# ————————————————————————————————————————————————————————————————
DEFAULT_IFACE   = "eth0"
CAPTURE_SECONDS = 20
PCAP_FALLBACK   = Path("traffic.pcap")                   # если live-захват невозможен

# ————————————————————————————————————————————————————————————————
#  Вспомогательные функции
# ————————————————————————————————————————————————————————————————
def inet_to_str(inet: bytes) -> str:
    """Читаемый IPv4-адрес из packed bytes."""
    return socket.inet_ntoa(inet)


def autodetect_iface_ip() -> tuple[str, str]:
    """
    Находит первый активный интерфейс (не loopback) и его IPv4.   
    Работает только под Linux. Если не найдено — RuntimeError.
    """
    if platform.system().lower() != "linux":
        raise NotImplementedError("Автовыбор интерфейса реализован только для Linux.")

    for iface in os.listdir("/sys/class/net/"):
        if iface == "lo":
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                ifreq = struct.pack("256s", iface.encode()[:15])
                ip_bytes = fcntl.ioctl(s.fileno(), 0x8915, ifreq)[20:24]  # SIOCGIFADDR
                ip = socket.inet_ntoa(ip_bytes)
                return iface, ip
        except OSError:
            continue
    raise RuntimeError("Не удалось определить активный интерфейс и IP.")


# ————————————————————————————————————————————————————————————————
#  Хранение статистики + вывод
# ————————————————————————————————————————————————————————————————
class CaptureStats:
    def __init__(self) -> None:
        self.outgoing: dict[str, int] = defaultdict(int)
        self.incoming: dict[str, int] = defaultdict(int)
        self.records: list[tuple[float, str]] = []          # (timestamp, proto)
        self.start_ts: float | None = None

    # добавление события
    def add(self, direction: str, proto: str, ts: float) -> None:
        if self.start_ts is None:
            self.start_ts = ts
        (self.outgoing if direction == "out" else self.incoming)[proto] += 1
        self.records.append((ts, proto))

    # итоговый отчёт + график
    def report(self, show_plot: bool = True) -> None:
        print("\n===== ИТОГОВАЯ СТАТИСТИКА =====")
        print(f"Исходящие: {sum(self.outgoing.values()):>6}  {dict(self.outgoing)}")
        print(f"Входящие : {sum(self.incoming.values()):>6}  {dict(self.incoming)}")

        if len(self.records) < 2:
            print("Недостаточно пакетов для анализа.")
            return

        # интервалы
        ts_sorted = sorted(ts for ts, _ in self.records)
        intervals = [b - a for a, b in zip(ts_sorted, ts_sorted[1:])]
        print("\nИнтервалы между соседними пакетами:")
        print(f"   средний : {sum(intervals)/len(intervals):.6f} с")
        print(f"   максимум: {max(intervals):.6f} с")
        print(f"   минимум : {min(intervals):.6f} с")

        # агрегация по секундам
        base = int(self.start_ts)
        per_sec_tcp: dict[int, int] = defaultdict(int)
        per_sec_udp: dict[int, int] = defaultdict(int)
        for ts, proto in self.records:
            sec = int(ts) - base
            (per_sec_tcp if proto == "TCP" else per_sec_udp)[sec] += 1

        print("\nРаспределение по секундам (offset → TCP/UDP):")
        for s in sorted(set(per_sec_tcp) | set(per_sec_udp)):
            print(f"  +{s:>2} с: {per_sec_tcp.get(s,0):>4} TCP | {per_sec_udp.get(s,0):>4} UDP")

        if show_plot:
            secs = sorted(set(per_sec_tcp) | set(per_sec_udp))
            plt.figure(figsize=(10, 4))
            plt.plot(secs, [per_sec_tcp.get(s, 0) for s in secs],
                     label="TCP", marker="o", linewidth=1.5)
            plt.plot(secs, [per_sec_udp.get(s, 0) for s in secs],
                     label="UDP", marker="o", linewidth=1.5)
            plt.title("Временное распределение исходящих IPv4-пакетов (TCP / UDP)")
            plt.xlabel("Секунды от начала захвата")
            plt.ylabel("Количество пакетов")
            plt.grid(alpha=0.3)
            plt.legend()
            plt.tight_layout()
            plt.show()


# ————————————————————————————————————————————————————————————————
#  Обработка одного пакета
# ————————————————————————————————————————————————————————————————
def handle_packet(ts: float, buf: bytes, direction: str,
                  stats: CaptureStats) -> None:
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data                       # type: ignore[attr-defined]
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return
    if not isinstance(ip, dpkt.ip.IP):
        return

    proto = "TCP" if isinstance(ip.data, dpkt.tcp.TCP) else \
            "UDP" if isinstance(ip.data, dpkt.udp.UDP) else None
    if proto is None:
        return

    src, dst = inet_to_str(ip.src), inet_to_str(ip.dst)
    dir_label = "OUT" if direction == "out" else "IN "
    stats.add(direction, proto, ts)
    print(f"[{time.strftime('%H:%M:%S', time.localtime(ts))}] {dir_label} {src} → {dst}")


# ————————————————————————————————————————————————————————————————
#  Источники пакетов
# ————————————————————————————————————————————————————————————————
def live_packets(iface: str, duration: int) -> Iterator[Tuple[float, bytes]]:
    """Генератор live-пакетов с интерфейса (требует raw-доступа)."""
    if pylibpcap is None:
        sys.exit("Модуль «pcap» не найден. Установите pylibpcap / pcap-ct.")
    pc = pylibpcap.pcap(name=iface, promisc=True, immediate=True, timeout_ms=50)
    stop_at = time.time() + duration
    for ts, raw in pc:
        if ts >= stop_at:
            break
        yield ts, raw


def file_packets(path: Path) -> Iterator[Tuple[float, bytes]]:
    """Генератор пакетов из pcap-файла."""
    if not path.exists():
        sys.exit(f"Файл {path} не найден.")
    with path.open("rb") as f:
        for ts, buf in dpkt.pcap.Reader(f):
            yield ts, buf


# ————————————————————————————————————————————————————————————————
#  main()
# ————————————————————————————————————————————————————————————————
def main() -> None:
    print("===== TCP/UDP DATAGRAM ANALYZER (with plot) =====\n")

    try:
        iface, local_ip = autodetect_iface_ip()
    except Exception as e:
        print(f"[WARN] Автовыбор не удался: {e}")
        iface, local_ip = DEFAULT_IFACE, "0.0.0.0"

    print(f"[ИНФО] Используем интерфейс: {iface}, IP: {local_ip}")

    # Пытаемся захватить live-трафик
    use_live = True
    try:
        packets_iter: Iterator[Tuple[float, bytes]] = live_packets(iface, CAPTURE_SECONDS)
        print(f"\nЗахват исходящих пакетов на {iface} (⏱ {CAPTURE_SECONDS} с)…\n")
    except (OSError, SystemExit):
        print("[WARN] Live-захват недоступен (нет прав?). Переходим к pcap-файлу.")
        use_live = False
        packets_iter = file_packets(PCAP_FALLBACK)
        print(f"\nАнализ пакетов из файла «{PCAP_FALLBACK}»…\n")

    stats = CaptureStats()
    for ts, buf in packets_iter:
        # Исходящий (out) ↔ адрес источника совпал с нашим IP
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data if isinstance(eth.data, dpkt.ip.IP) else None
        if ip and inet_to_str(ip.src) == local_ip:
            handle_packet(ts, buf, "out", stats)
        elif ip and inet_to_str(ip.dst) == local_ip:
            handle_packet(ts, buf, "in", stats)

    stats.report(show_plot=True)


# ————————————————————————————————————————————————————————————————
if __name__ == "__main__":
    main()
