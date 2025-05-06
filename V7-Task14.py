#!/usr/bin/env python3
"""
TASK-14 — входящий трафик с самопроверкой (25 с):
паузa 1 с, 4 фазы по 100 pkt (TCP-IN @+2 c, UDP-IN @+4 c)
"""

from __future__ import annotations
import os, sys, time, socket, struct, fcntl, platform, random, threading
from importlib import util as import_util
import dpkt, matplotlib.pyplot as plt

# ── параметры ───────────────────────────────────────────────────────────────
PAUSE, BURST, POST = 1, 4, 20
TOTAL_SEC          = PAUSE + BURST + POST                 # 25 s
BURST_PKTS         = 100
SEND_DELAY         = 0.006
TEST_IP            = "192.0.2.1"
TCP_PROTO, UDP_PROTO = 6, 17

# ── вспом. утилиты ──────────────────────────────────────────────────────────
def inet(b: bytes) -> str: return socket.inet_ntoa(b)

def iface_ip_mac() -> tuple[str, str, bytes]:
    if platform.system().lower() != "linux":
        sys.exit("Только Linux.")
    for iface in os.listdir("/sys/class/net"):
        if iface == "lo": continue
        try:
            # IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                ifreq = struct.pack("256s", iface.encode()[:15])
                ip = inet(fcntl.ioctl(s.fileno(), 0x8915, ifreq)[20:24])
            # MAC
            with open(f"/sys/class/net/{iface}/address") as f:
                mac = bytes.fromhex(f.read().strip().replace(":", ""))
            return iface, ip, mac
        except (OSError, FileNotFoundError):
            continue
    sys.exit("Не найден внешний интерфейс.")

def csum(b: bytes) -> int:
    if len(b) & 1: b += b"\0"
    s = sum(struct.unpack("!%dH"%(len(b)//2), b))
    s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return (~s) & 0xFFFF

# ── построение кадров (Ethernet + IP + TCP/UDP) ─────────────────────────────
def eth_ip_hdr(src_mac: bytes, dst_mac: bytes,
               src_ip: str, dst_ip: str,
               proto: int, plen: int) -> bytes:
    eth = dst_mac + src_mac + b"\x08\x00"      # EtherType=IPv4
    ip  = struct.pack("!BBHHHBBH4s4s",
          0x45, 0, 20+plen, random.randint(0,65535), 0,
          64, proto, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip  = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return eth + ip

def tcp_seg(sport: int, dport: int) -> bytes:
    return struct.pack("!HHLLBBHHH",
        sport, dport, random.randint(0,0xffffffff), 0, 5<<4, 0x02, 65535, 0, 0)

def udp_seg(sport: int, dport: int) -> bytes:
    return struct.pack("!HHHHB", sport, dport, 9, 0, 0x42)

def build_frame(src_mac: bytes, dst_mac: bytes,
                src_ip: str, dst_ip: str,
                proto: str, sport: int, dport: int) -> bytes:
    l4 = tcp_seg(sport, dport) if proto=="TCP" else udp_seg(sport, dport)
    p  = TCP_PROTO if proto=="TCP" else UDP_PROTO
    return eth_ip_hdr(src_mac, dst_mac, src_ip, dst_ip, p, len(l4)) + l4

# ── генерация 4-фазного всплеска (TX→RX эхо) ────────────────────────────────
def launch_burst(iface: str, local_ip: str, local_mac: bytes):
    # Запрашиваем MAC-адрес шлюза из arp-кеша (или берём broadcast)
    try:
        with open('/proc/net/arp') as f:
            gw_mac = next(iter(f)).encode()  # just to trigger StopIteration
    except StopIteration:
        gw_mac = b"\xff\xff\xff\xff\xff\xff"
    else:
        gw_mac = b"\xff\xff\xff\xff\xff\xff"
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))

    def send_phase(proto:str, direction:str):
        sport0 = random.randint(20000,60000)
        frames=[]
        for i in range(BURST_PKTS):
            sport=sport0+i
            if direction=="in":
                frame = build_frame(src_mac=gw_mac, dst_mac=local_mac,
                                    src_ip=TEST_IP, dst_ip=local_ip,
                                    proto=proto, sport=sport, dport=80)
            else:  # out
                frame = build_frame(src_mac=local_mac, dst_mac=gw_mac,
                                    src_ip=local_ip, dst_ip=TEST_IP,
                                    proto=proto, sport=sport, dport=80)
            frames.append(frame)
        for fr in frames:
            s.send(fr); time.sleep(SEND_DELAY)

    def burst_thread():
        time.sleep(PAUSE)
        phases=[("TCP","out"),("TCP","in"),("UDP","out"),("UDP","in")]
        for proto,dir_ in phases:
            t0=time.time(); send_phase(proto,dir_)
            time.sleep(max(0,1-(time.time()-t0)))
    threading.Thread(target=burst_thread,daemon=True).start()

# ── захват через pylibpcap (как в Task-13) ──────────────────────────────────
pylibpcap=None
if (sp:=import_util.find_spec("pcap")) and sp.origin:
    import importlib; pylibpcap=importlib.import_module("pcap")      # type: ignore

def sniff(iface:str,sec:int):
    if not pylibpcap: sys.exit("pylibpcap + sudo required")
    pc=pylibpcap.pcap(name=iface,promisc=True,immediate=True,timeout_ms=0)
    end=time.time()+sec
    try:
        while time.time()<end:
            try: ts,raw=pc.recv(timeout_ms=100)
            except (BlockingIOError,OSError): continue
            if ts: yield ts,raw
    except AttributeError:
        for ts,raw in pc:
            if time.time()>=end: break
            yield ts,raw

# ── статистика — аналогична Task-13, но проверяем IN-фазы ───────────────────
class Stat:
    def __init__(self):
        self.tcp=[0]*(TOTAL_SEC+1); self.udp=[0]*(TOTAL_SEC+1)
    def add(self,proto:str,dt:float):
        sec=int(dt)+1
        if sec<=TOTAL_SEC:
            (self.tcp if proto=="TCP" else self.udp)[sec]+=1
    def report(self):
        print("\n===== ИТОГО =====")
        print(f"Ожидалось/поймано TCP-IN @+3 с : {BURST_PKTS}/{self.tcp[3]}")
        print(f"Ожидалось/поймано UDP-IN @+5 с : {BURST_PKTS}/{self.udp[5]}\n")
        print("Распределение (+offset → TCP | UDP):")
        for s in range(TOTAL_SEC+1):
            print(f" +{s:>2} с: {self.tcp[s]:4} TCP | {self.udp[s]:4} UDP")
        plt.figure(figsize=(10,4))
        plt.plot(range(TOTAL_SEC+1),self.tcp,label="TCP",marker="o")
        plt.plot(range(TOTAL_SEC+1),self.udp,label="UDP",marker="o")
        plt.title("Временное распределение входящих IPv4-дейтаграмм")
        plt.xlabel("Секунды"); plt.ylabel("Пакеты")
        plt.grid(alpha=.3); plt.legend(); plt.tight_layout(); plt.show()

# ── main ────────────────────────────────────────────────────────────────────
def main():
    iface,local_ip,local_mac = iface_ip_mac()
    print(f"[iface] {iface}  IP={local_ip}  MAC={':'.join(f'{b:02x}' for b in local_mac)}")
    launch_burst(iface, local_ip, local_mac)
    st=Stat(); t0=time.time()
    for ts,raw in sniff(iface,TOTAL_SEC):
        eth=dpkt.ethernet.Ethernet(raw)
        if not isinstance(eth.data,dpkt.ip.IP): continue
        ip4=eth.data
        if inet(ip4.dst)!=local_ip: continue             # ВХОДЯЩИЕ
        proto="TCP" if isinstance(ip4.data,dpkt.tcp.TCP) else \
              "UDP" if isinstance(ip4.data,dpkt.udp.UDP) else None
        if not proto: continue
        print(f"{time.strftime('%H:%M:%S',time.localtime(ts))}  "
              f"{inet(ip4.src)} → {inet(ip4.dst)}  {proto}")
        st.add(proto, ts-t0)
    st.report()

if __name__=="__main__":
    main()
