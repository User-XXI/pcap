"""
* Задание 13
    1) Исходящмй трафик
    2) Работаем с текущим трафиком, а не с предзаписанным файлом
    3) Длительность захвата пакетов 20 секунд
    4) Сетевой интерфейс для захвата eth0
    5) ip адрес 192.168.222.112
"""
from __future__ import annotations
import socket
import sys
import time
from collections import defaultdict
from importlib import util as import_util
from pathlib import Path
from typing import Iterator, Tuple
import dpkt  # разбор пакетов / pcap
import matplotlib.pyplot as plt
import os
import struct
import fcntl
import platform

# ————————————————————————————————————————————————————————————————
#  Безопасный импорт pylibpcap
# ————————————————————————————————————————————————————————————————
pylibpcap = None
_spec = import_util.find_spec("pcap")
if _spec and _spec.origin and Path(_spec.origin).resolve() != Path(__file__).resolve():
    import importlib
    pylibpcap = importlib.import_module("pcap")  # type: ignore
# ————————————————————————————————————————————————————————————————
#  Константы по умолчанию
# ————————————————————————————————————————————————————————————————
DEFAULT_DURATION = 15
PCAP_FILE_DEFAULT = Path("traffic.pcap")
# ————————————————————————————————————————————————————————————————
#  Утилиты
# ————————————————————————————————————————————————————————————————
def inet_to_str(inet: bytes) -> str:
    return socket.inet_ntoa(inet)
# ————————————————————————————————————————————————————————————————
#  Класс статистики
# ————————————————————————————————————————————————————————————————
def get_iface_and_ip() -> tuple[str, str]:
    """Определяет активный интерфейс и его IP-адрес (исключая loopback)."""
    if platform.system().lower() != "linux":
        raise NotImplementedError("Автоопределение IP работает только на Linux")
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
    raise RuntimeError("Не найден активный интерфейс с IP")

class CaptureStats:
    """Хранит данные и строит график."""
    def __init__(self) -> None:
        self.outgoing = defaultdict(int)
        self.incoming = defaultdict(int)
        self.records: list[tuple[float, str]] = []  # (timestamp, proto)
        self.start_ts: float | None = None
    def add(self, direction: str, proto: str, ts: float) -> None:
        if self.start_ts is None:
            self.start_ts = ts
        (self.outgoing if direction == "out" else self.incoming)[proto] += 1
        self.records.append((ts, proto))
    # ——— итог + график ———
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
        # агрегируем по секундам и протоколам
        base = int(self.start_ts) if self.start_ts else 0
        per_sec_tcp: dict[int, int] = defaultdict(int)
        per_sec_udp: dict[int, int] = defaultdict(int)
        for ts, proto in self.records:
            sec = int(ts) - base
            if proto == "TCP":
                per_sec_tcp[sec] += 1
            else:
                per_sec_udp[sec] += 1
        # вывод распределения (текст)
        print("\nРаспределение по секундам (offset → TCP/UDP):")
        all_secs = sorted(set(per_sec_tcp) | set(per_sec_udp))
        for s in all_secs:
            print(f"  +{s:>2} с: {per_sec_tcp.get(s, 0):>4} TCP | {per_sec_udp.get(s, 0):>4} UDP")
        # график
        if show_plot:
            secs = all_secs
            tcp_counts = [per_sec_tcp.get(s, 0) for s in secs]
            udp_counts = [per_sec_udp.get(s, 0) for s in secs]
            plt.figure(figsize=(10, 4))
            plt.plot(secs, tcp_counts, label="TCP", marker="o", linewidth=1.5, color="tab:green")
            plt.plot(secs, udp_counts, label="UDP", marker="o", linewidth=1.5, color="tab:red")
            plt.title(f"Временное распределение исходящих IPv4 дейтаграмм с разделением пакетов по \nпротоколам TCP и UDP транспортного уровня модели OSI")
            plt.xlabel("Секунды")
            plt.ylabel("Пакеты")
            plt.grid(True, alpha=0.3)
            plt.legend()
            plt.tight_layout()
            plt.show()
# ————————————————————————————————————————————————————————————————
#  Обработчик пакетов
# ————————————————————————————————————————————————————————————————
def handle_packet(ts: float, buf: bytes, mode: str, stats: CaptureStats, LOCAL_IP: str) -> None:
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return
    if not isinstance(eth.data, dpkt.ip.IP):
        return
    ip = eth.data
    proto = (
        "TCP" if isinstance(ip.data, dpkt.tcp.TCP) else
        "UDP" if isinstance(ip.data, dpkt.udp.UDP) else None
    )
    if proto is None:
        return
    src, dst = inet_to_str(ip.src), inet_to_str(ip.dst)
    if mode == "outgoing" and src == LOCAL_IP:
        stats.add("out", proto, ts)
        direction = "OUT"
    elif mode == "incoming" and dst == LOCAL_IP:
        stats.add("in", proto, ts)
        direction = "IN "
    else:
        return
    print(f"[{time.strftime('%H:%M:%S', time.localtime(ts))}] {direction} {src} -> {dst}")
# ————————————————————————————————————————————————————————————————
#  Источники пакетов
# ————————————————————————————————————————————————————————————————
def live_packets(iface: str, duration: int) -> Iterator[Tuple[float, bytes]]:
    if pylibpcap is None:
        sys.exit("Установите ‘pylibpcap’ и запустите с sudo для live-захвата.")
    pc = pylibpcap.pcap(name=iface, promisc=True, immediate=True, timeout_ms=50)
    stop_at = time.time() + duration
    for ts, raw in pc:
        if ts >= stop_at:
            break
        yield ts, raw
def file_packets(path: Path) -> Iterator[Tuple[float, bytes]]:
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
    # режим
    while True:
        # mode = input("Режим (outgoing/incoming) [outgoing]: ").strip().lower() or "outgoing"
        mode = "outgoing"
        if mode in {"outgoing", "incoming"}:
            break
        print("Введите outgoing или incoming.")
    # источник
    # src_choice = input("Источник: 1-live | 2-pcap  [1]: ").strip() or "1"
    src_choice = "1"
    if src_choice == "1":
        try:
            # duration = int(input(f"Длительность, сек [{DEFAULT_DURATION}]: ") or DEFAULT_DURATION)
            duration = 20
        except ValueError:
            duration = DEFAULT_DURATION
        try:
            iface, LOCAL_IP = get_iface_and_ip()
            print(f"[ИНФО] Интерфейс: {iface}, IP: {LOCAL_IP}")
        except Exception as e:
            sys.exit(f"[ОШИБКА] {e}")

        packets = live_packets(iface, duration)
        print(f"\nЗахват {mode}-пакетов на {iface} (⏱ {duration} с)…\n")
    else:
        pcap_path = Path(input(f"Файл pcap [{PCAP_FILE_DEFAULT}]: ").strip() or PCAP_FILE_DEFAULT)
        packets = file_packets(pcap_path)
        print(f"\nАнализ {mode}-пакетов из {pcap_path}…\n")
    stats = CaptureStats()
    for ts, buf in packets:
        handle_packet(ts, buf, mode, stats, LOCAL_IP)
    stats.report(show_plot=True)
if __name__ == "__main__":
    main()

