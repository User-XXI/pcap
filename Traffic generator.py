#!/usr/bin/env python3
import socket
import threading
import time

# Настройки
HOST = "127.0.0.1"
PORT_TCP_IN = 12345
PORT_TCP_OUT = 12346
PORT_UDP_IN = 12347
PORT_UDP_OUT = 12348

DURATION = 4  # секунд на фазу

# ————————————————————————————————————————————————————————————————
# TCP SERVER
# ————————————————————————————————————————————————————————————————
def tcp_server(port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, port))
        server.listen()
        server.settimeout(DURATION + 1)
        try:
            conn, _ = server.accept()
            with conn:
                start = time.time()
                while time.time() - start < DURATION:
                    data = conn.recv(1024)
                    if not data:
                        break
        except socket.timeout:
            pass

# ————————————————————————————————————————————————————————————————
# TCP CLIENT
# ————————————————————————————————————————————————————————————————
def tcp_client(port: int):
    # time.sleep(0.2)  # дать серверу подняться
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(1)
        try:
            client.connect((HOST, port))
        except:
            return
        start = time.time()
        while time.time() - start < DURATION:
            try:
                client.sendall(b"A" * 512)
            except:
                break
            # time.sleep(0.01)

# ————————————————————————————————————————————————————————————————
# UDP SERVER
# ————————————————————————————————————————————————————————————————
def udp_server(port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, port))
        server.settimeout(DURATION + 1)
        start = time.time()
        while time.time() - start < DURATION:
            try:
                server.recvfrom(1024)
            except socket.timeout:
                break
            except:
                continue

# ————————————————————————————————————————————————————————————————
# UDP CLIENT
# ————————————————————————————————————————————————————————————————
def udp_client(port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        start = time.time()
        while time.time() - start < DURATION:
            client.sendto(b"B" * 512, (HOST, port))
            # time.sleep(0.01)

# ————————————————————————————————————————————————————————————————
# Один этап: запуск клиент-серверных потоков
# ————————————————————————————————————————————————————————————————
def run_phase(name: str, client_func, server_func, port: int):
    print(f"[{time.strftime('%H:%M:%S')}] ▶️ {name}")
    threads = [
        threading.Thread(target=server_func, args=(port,), daemon=True),
        threading.Thread(target=client_func, args=(port,), daemon=True)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

# ————————————————————————————————————————————————————————————————
# MAIN
# ————————————————————————————————————————————————————————————————
def main():
    run_phase("1) TCP IN", tcp_client, tcp_server, PORT_TCP_IN)
    # time.sleep(0.5)
    run_phase("2) TCP OUT", tcp_server, tcp_client, PORT_TCP_OUT)
    # time.sleep(0.5)
    run_phase("3) UDP IN", udp_client, udp_server, PORT_UDP_IN)
    # time.sleep(0.5)
    run_phase("4) UDP OUT", udp_server, udp_client, PORT_UDP_OUT)
    print("✅ Генерация завершена.")

if __name__ == "__main__":
    main()
