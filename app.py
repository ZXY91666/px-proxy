"""
万能 PaaS 代理服务 —— 部署到 Koyeb/Render/Fly.io/Zeabur 等免费平台。
功能：
1. HTTP CONNECT 代理（最通用）
2. SOCKS5 代理
3. 健康检查

部署后在境外节点上跑，提供干净的境外出口。

启动：python app.py
平台会设 PORT 环境变量。
"""
import os
import socket
import select
import threading
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", 8080))
USER = os.environ.get("PROXY_USER", "")
PASS = os.environ.get("PROXY_PASS", "")

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("proxy")

BUFSIZE = 65536


class ConnectHandler(BaseHTTPRequestHandler):
    """HTTP CONNECT 代理（HTTPS 走这个）。"""

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log.info("%s - %s" % (self.address_string(), fmt % args))

    def _check_auth(self):
        if not USER:
            return True
        auth = self.headers.get("Proxy-Authorization", "")
        if not auth.startswith("Basic "):
            return False
        import base64
        try:
            dec = base64.b64decode(auth[6:]).decode()
            u, p = dec.split(":", 1)
            return u == USER and p == PASS
        except Exception:
            return False

    def do_CONNECT(self):
        if not self._check_auth():
            self.send_response(407)
            self.send_header("Proxy-Authenticate", 'Basic realm="proxy"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        host, _, port = self.path.partition(":")
        try:
            port = int(port or 443)
        except Exception:
            port = 443

        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except Exception as e:
            log.warning("connect %s:%s failed: %s", host, port, e)
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self.send_response(200, "Connection Established")
        self.send_header("Proxy-Agent", "paas-proxy")
        self.end_headers()

        self.wfile.flush()
        self._tunnel(self.connection, upstream)

    def do_GET(self):
        """普通 HTTP 代理请求。"""
        if not self._check_auth():
            self.send_response(407)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # 健康检查
        if self.path in ("/", "/health", "/ping"):
            body = b'{"ok":true,"proxy":"paas","port":%d}' % PORT
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # 转发 HTTP
        self._proxy_http()

    def _proxy_http(self):
        from urllib.parse import urlparse
        u = urlparse(self.path)
        if not u.netloc:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        host = u.hostname
        port = u.port or 80
        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except Exception:
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        req = f"{self.command} {path} HTTP/1.1\r\n"
        for k, v in self.headers.items():
            if k.lower() in ("proxy-connection", "proxy-authorization"):
                continue
            req += f"{k}: {v}\r\n"
        req += "\r\n"
        upstream.sendall(req.encode())

        while True:
            r, _, _ = select.select([upstream], [], [], 30)
            if not r:
                break
            data = upstream.recv(BUFSIZE)
            if not data:
                break
            self.wfile.write(data)
            self.wfile.flush()
        upstream.close()

    def _tunnel(self, client, upstream):
        """双向转发。"""
        socks = [client, upstream]
        try:
            while True:
                r, _, x = select.select(socks, [], socks, 60)
                if x:
                    break
                if not r:
                    continue
                for s in r:
                    other = upstream if s is client else client
                    try:
                        data = s.recv(BUFSIZE)
                    except Exception:
                        return
                    if not data:
                        return
                    try:
                        other.sendall(data)
                    except Exception:
                        return
        finally:
            try:
                upstream.close()
            except Exception:
                pass


class Socks5Handler(threading.Thread):
    """SOCKS5 代理（简化实现）。"""

    def __init__(self, conn, addr):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr

    def run(self):
        try:
            self._handle()
        except Exception:
            pass
        finally:
            try:
                self.conn.close()
            except Exception:
                pass

    def _handle(self):
        c = self.conn
        c.settimeout(30)
        # 握手
        ver_n = c.recv(2)
        if len(ver_n) < 2 or ver_n[0] != 5:
            return
        nm = ver_n[1]
        c.recv(nm)
        c.sendall(b"\x05\x00")  # 无认证

        # 请求
        hdr = c.recv(4)
        if len(hdr) < 4:
            return
        ver, cmd, rsv, atyp = hdr
        if atyp == 1:
            addr = socket.inet_ntoa(c.recv(4))
        elif atyp == 3:
            ln = c.recv(1)[0]
            addr = c.recv(ln).decode()
        elif atyp == 4:
            addr = socket.inet_ntop(socket.AF_INET6, c.recv(16))
        else:
            return
        port = int.from_bytes(c.recv(2), "big")

        if cmd != 1:  # 只支持 CONNECT
            c.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return

        try:
            up = socket.create_connection((addr, port), timeout=15)
        except Exception:
            c.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            return

        c.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)

        # 转发
        socks = [c, up]
        while True:
            r, _, x = select.select(socks, [], socks, 60)
            if x or not r:
                break
            for s in r:
                other = up if s is c else c
                try:
                    data = s.recv(BUFSIZE)
                except Exception:
                    return
                if not data:
                    return
                try:
                    other.sendall(data)
                except Exception:
                    return
        up.close()


def socks5_server(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(128)
    log.info("SOCKS5 listening on %d", port)
    while True:
        conn, addr = srv.accept()
        Socks5Handler(conn, addr).start()


def main():
    log.info("=== PaaS Proxy starting ===")
    log.info("HTTP CONNECT port: %d", PORT)
    if USER:
        log.info("auth: %s:***", USER)

    # SOCKS5 跑在 PORT+1
    try:
        threading.Thread(target=socks5_server, args=(PORT + 1,),
                         daemon=True).start()
    except Exception as e:
        log.warning("socks5 failed: %s", e)

    srv = ThreadingHTTPServer(("0.0.0.0", PORT), ConnectHandler)
    srv.daemon_threads = True
    log.info("HTTP proxy listening on %d", PORT)
    srv.serve_forever()


if __name__ == "__main__":
    main()
