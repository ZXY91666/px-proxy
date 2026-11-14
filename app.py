"""
单端口混合代理：同一个端口自动识别 HTTP CONNECT / SOCKS5 / 普通 HTTP。
这样 Railway 的 TCP proxy 和 HTTP 域名都能用。
"""
import os
import socket
import struct
import select
import threading
import logging
import time

PORT = int(os.environ.get("PORT", 8080))
BUF = 65536

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("mix")


def pipe(a, b):
    socks = [a, b]
    try:
        while True:
            r, _, x = select.select(socks, [], socks, 300)
            if x or not r:
                return
            for s in r:
                other = b if s is a else a
                try:
                    data = s.recv(BUF)
                except Exception:
                    return
                if not data:
                    return
                try:
                    other.sendall(data)
                except Exception:
                    return
    finally:
        for s in (a, b):
            try:
                s.close()
            except Exception:
                pass


def handle_http(client, first):
    """HTTP 代理：CONNECT 或绝对 URI。"""
    buf = first
    while b"\r\n\r\n" not in buf:
        c = client.recv(4096)
        if not c:
            client.close()
            return
        buf += c
        if len(buf) > 65536:
            break

    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin1", "ignore")
    lines = head.split("\r\n")
    if not lines:
        client.close()
        return
    parts = lines[0].split()
    if len(parts) < 2:
        client.close()
        return
    method, target = parts[0], parts[1]

    # 健康检查
    if method == "GET" and target in ("/", "/health", "/ping"):
        body = b'{"ok":true,"mode":"mixed"}'
        client.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                       b"Content-Length: " + str(len(body)).encode() +
                       b"\r\nConnection: close\r\n\r\n" + body)
        client.close()
        return

    if method.upper() == "CONNECT":
        host, _, port_s = target.rpartition(":")
        if not host:
            host, port_s = target, "443"
        try:
            port = int(port_s)
        except Exception:
            port = 443
        try:
            up = socket.create_connection((host, port), timeout=25)
        except Exception as e:
            log.warning("CONNECT %s:%s fail %s", host, port, e)
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            client.close()
            return
        log.info("CONNECT %s:%s OK", host, port)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        pipe(client, up)
        return

    # 普通 HTTP
    if not target.startswith("http://"):
        client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        client.close()
        return
    rest = target[7:]
    if "/" in rest:
        hostport, path = rest.split("/", 1)
        path = "/" + path
    else:
        hostport, path = rest, "/"
    if ":" in hostport:
        host, port_s = hostport.rsplit(":", 1)
        port = int(port_s)
    else:
        host, port = hostport, 80
    try:
        up = socket.create_connection((host, port), timeout=25)
    except Exception:
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        client.close()
        return
    out = [f"{method} {path} HTTP/1.1"]
    for ln in lines[1:]:
        low = ln.lower()
        if low.startswith(("proxy-connection:", "proxy-authorization:")):
            continue
        out.append(ln)
    up.sendall(("\r\n".join(out) + "\r\n\r\n").encode())
    # 把已读的额外 body 转发
    rest_body = buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in buf else b""
    if rest_body:
        up.sendall(rest_body)
    pipe(client, up)


def handle_socks5(client, first):
    """SOCKS5。first 是已读的 2 字节（VER, NMETHODS）。"""
    ver, n = first[0], first[1]
    if ver != 5:
        client.close()
        return
    methods = b""
    while len(methods) < n:
        c = client.recv(n - len(methods))
        if not c:
            client.close()
            return
        methods += c
    client.sendall(b"\x05\x00")

    hdr = b""
    while len(hdr) < 4:
        c = client.recv(4 - len(hdr))
        if not c:
            client.close()
            return
        hdr += c
    cmd, atyp = hdr[1], hdr[3]

    if atyp == 1:
        addr = socket.inet_ntoa(client.recv(4))
    elif atyp == 3:
        ln = client.recv(1)[0]
        addr = client.recv(ln).decode()
    elif atyp == 4:
        addr = socket.inet_ntop(socket.AF_INET6, client.recv(16))
    else:
        client.close()
        return
    port = int.from_bytes(client.recv(2), "big")

    if cmd != 1:
        client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
        client.close()
        return

    try:
        up = socket.create_connection((addr, port), timeout=25)
    except Exception:
        client.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
        client.close()
        return

    client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
    log.info("SOCKS %s:%s OK", addr, port)
    pipe(client, up)


def handle(client, addr):
    try:
        client.settimeout(60)
        first = client.recv(2)
        if not first:
            client.close()
            return
        if first[0] == 5:
            handle_socks5(client, first)
        else:
            handle_http(client, first)
    except Exception as e:
        log.warning("handle err %s", str(e)[:60])
        try:
            client.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(256)
    log.info("=== mixed proxy listening on %d ===", PORT)
    while True:
        try:
            c, a = srv.accept()
            threading.Thread(target=handle, args=(c, a), daemon=True).start()
        except Exception:
            continue


if __name__ == "__main__":
    main()
