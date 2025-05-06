#!/usr/bin/env python3
"""
* Задание 13 – анализ исходящего трафика с самопроверкой
  0-1 с  : пауза
  1-2 с  : 100 TCP-OUT  (src = local_ip, dst = 192.0.2.1, dport=80)
  2-3 с  : 100 TCP-IN   (не видим, т.к. фильтруем only OUT)
  3-4 с  : 100 UDP-OUT  (src = local_ip, dst = 192.0.2.1, dport=80)
  4-5 с  : 100 UDP-IN   (не видим)
  5-25 с : пассивный захват
"""

from __future__ import annotations
import os, sys, time, socket, struct, fcntl, platform, random, threading
from collections import defaultdict
from importlib import util as import_util
from typing import Iterator, Tuple
import dpkt, matplotlib.pyplot as plt

# ─────── Параметры ──────────────────────────────────────────────────────────
PAUSE_SEC     = 1
BURST_SEC     = 4
POST_SEC      = 20
TOTAL_SEC     = PAUSE_SEC + BURST_SEC + POST_SEC     # 25 с

BURST_PKTS    = 100       # ← Сколько тест-пакетов генерировать в фазе
SEND_DELAY    = 0.006     # Задержка между кадрами, чтобы не терялись

TEST_REMOTE_IP = "192.0.2.1"
TCP_PROTO, UDP_PROTO = 6, 17          # номера протоколов в IP-заголовке

# ─────── Генерация контрольного трафика ─────────────────────────────────────
def _csum(b: bytes) -> int:
    if len(b) & 1: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b)//2), b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF

def _ip_hdr(src: str, dst: str, proto: int, pay_len: int) -> bytes:
    base = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, 20+pay_len, random.randint(0,65535), 0,
        64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return base[:10] + struct.pack("!H", _csum(base)) + base[12:]

def _tcp_seg(sport:int, dport:int)->bytes:
    return struct.pack("!HHLLBBHHH",
        sport, dport, random.randint(0,0xFFFFFFFF), 0,
        5<<4, 0x02, 65535, 0, 0)               # SYN, пустая сумма

def _udp_seg(sport:int, dport:int)->bytes:
    return struct.pack("!HHHHB", sport, dport, 9, 0, 0x58)  # 1 байт payload

def _pkt(src:str, dst:str, proto:str, sport:int, dport:int)->bytes:
    seg  = _tcp_seg(sport,dport) if proto=="TCP" else _udp_seg(sport,dport)
    pnum = TCP_PROTO if proto=="TCP" else UDP_PROTO
    return _ip_hdr(src,dst,pnum,len(seg))+seg

def _burst(proto:str, direction:str, local_ip:str):
    dport=80
    sport0=random.randint(20000,60000)
    pkts=[ _pkt(local_ip,TEST_REMOTE_IP,proto,sport0+i,dport)
           if direction=="out"
           else _pkt(TEST_REMOTE_IP,local_ip,proto,sport0+i,dport)
           for i in range(BURST_PKTS)]
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        dst = TEST_REMOTE_IP if direction=="out" else local_ip
        for p in pkts:
            s.sendto(p,(dst,0)); time.sleep(SEND_DELAY)

def launch_burst_thread(local_ip:str):
    phases=[("TCP","out"),("TCP","in"),("UDP","out"),("UDP","in")]
    def runner():
        time.sleep(PAUSE_SEC)
        for proto,dir_ in phases:
            t0=time.time(); _burst(proto,dir_,local_ip)
            time.sleep(max(0,1-(time.time()-t0)))
    threading.Thread(target=runner,daemon=True).start()

# ─────── Сетевые утилиты ────────────────────────────────────────────────────
def inet(b:bytes)->str: return socket.inet_ntoa(b)

def get_iface_ip()->tuple[str,str]:
    if platform.system().lower()!="linux": sys.exit("Требуется Linux.")
    for iface in os.listdir("/sys/class/net"):
        if iface=="lo": continue
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                ifreq=struct.pack("256s",iface.encode()[:15])
                ip=socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,ifreq)[20:24])
                return iface,ip
        except OSError: pass
    sys.exit("Нет интерфейса с IPv4.")

# ─────── Захват через pylibpcap ─────────────────────────────────────────────
pylibpcap=None
if (sp := import_util.find_spec("pcap")) and sp.origin:
    import importlib; pylibpcap=importlib.import_module("pcap")      # type: ignore

def sniff(iface:str, secs:int)->Iterator[Tuple[float,bytes]]:
    if not pylibpcap: sys.exit("Установите pylibpcap + sudo.")
    pc=pylibpcap.pcap(name=iface,promisc=True,immediate=True,timeout_ms=0)
    end=time.time()+secs
    try:                                 # новый API
        while time.time()<end:
            try: ts,raw=pc.recv(timeout_ms=100)
            except (BlockingIOError,OSError): continue
            if ts: yield ts,raw
    except AttributeError:               # старый API – итератор
        for ts,raw in pc:
            if time.time()>=end: break
            yield ts,raw

# ─────── Счётчик и репортер ────────────────────────────────────────────────
class Stat:
    def __init__(self): self.t0=None; self.tcp=[]; self.udp=[]
    def _ensure(self,sec:int):
        while len(self.tcp)<=sec: self.tcp.append(0); self.udp.append(0)
    def add(self,proto:str,ts:float):
        if self.t0 is None: self.t0=ts
        sec=int(ts-self.t0)+1
        self._ensure(sec)
        (self.tcp if proto=="TCP" else self.udp)[sec]+=1
    def report(self):
        print("\n===== ИТОГ =====")
        exp_tcp=BURST_PKTS   # ожидаем TCP-OUT на +2 с
        exp_udp=BURST_PKTS   #         UDP-OUT на +4 с
        got_tcp=self.tcp[2] if len(self.tcp)>2 else 0
        got_udp=self.udp[4] if len(self.udp)>4 else 0
        print(f"Ожидалось / поймано TCP @+2 с : {exp_tcp} / {got_tcp}")
        print(f"Ожидалось / поймано UDP @+4 с : {exp_udp} / {got_udp}\n")
        max_sec=len(self.tcp)-1
        print("Распределение по секундам (+offset → TCP | UDP):")
        for s in range(max_sec+1):
            t=self.tcp[s] if s<len(self.tcp) else 0
            u=self.udp[s] if s<len(self.udp) else 0
            print(f" +{s:>2} с: {t:4} TCP | {u:4} UDP")
        # график
        plt.figure(figsize=(10,4))
        plt.plot(range(len(self.tcp)), self.tcp, label="TCP", marker="o")
        plt.plot(range(len(self.udp)), self.udp, label="UDP", marker="o")
        plt.title("Временное распределение исходящих IPv4-дейтаграмм")
        plt.xlabel("Секунды"); plt.ylabel("Пакеты")
        plt.grid(alpha=.3); plt.legend(); plt.tight_layout(); plt.show()

# ─────── main ──────────────────────────────────────────────────────────────
def main():
    iface,ip=get_iface_ip()
    print(f"[INFO] iface={iface}, ip={ip}")
    launch_burst_thread(ip)
    st=Stat()
    for ts,buf in sniff(iface,TOTAL_SEC):
        eth=dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data,dpkt.ip.IP): continue
        ip4=eth.data
        if inet(ip4.dst)!=ip: continue
        prot="TCP" if isinstance(ip4.data,dpkt.tcp.TCP) else \
             "UDP" if isinstance(ip4.data,dpkt.udp.UDP) else None
        if not prot: continue
        print(f"{time.strftime('%H:%M:%S',time.localtime(ts))}  "
              f"{inet(ip4.src)} → {inet(ip4.dst)}  {prot}")
        st.add(prot,ts)
    st.report()

if __name__=="__main__":
    main()
