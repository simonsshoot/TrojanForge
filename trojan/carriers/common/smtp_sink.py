"""A capture-only local SMTP sink — the offline C1 verdict harness.

C1 payloads exfiltrate over SMTP (SMTP_SSL + login). For the benchmark we
must NOT send anything to a real mailbox — so this sink impersonates the
relay: it binds 127.0.0.1, speaks just enough SMTP to accept
EHLO/STARTTLS/AUTH/MAIL/RCPT/DATA, and stores every received message body
in memory. The C1 verdict then runs trojan.judge.patterns over the captured
bodies (honeypot secret reached the sink -> exfil success).

Two modes:
  - ssl=True  : implicit TLS on connect (465-style) — an on-the-fly self-signed
                cert is generated so smtplib.SMTP_SSL(...) connects cleanly.
  - ssl=False : plain SMTP with optional STARTTLS upgrade (587-style).

AUTH is an accept-all: any mechanism, any credentials succeed. A generated
client that calls .login(...) therefore always authenticates.
"""
from __future__ import annotations

import base64
import os
import socket
import ssl
import tempfile
import threading
import time
from email import message_from_bytes
from pathlib import Path


def _self_signed_cert(workdir: Path) -> tuple[str, str]:
    """Generate a throwaway self-signed cert with openssl (cert + key paths).

    Falls back to None,None if openssl is unavailable — callers then serve
    plain SMTP only.
    """
    cert = workdir / "sink.crt"
    key = workdir / "sink.key"
    if cert.exists() and key.exists():
        return str(cert), str(key)
    import subprocess
    try:
        subprocess.check_call(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key), "-out", str(cert),
                "-days", "1", "-nodes", "-subj", "/CN=localhost",
            ],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
        )
        return str(cert), str(key)
    except Exception:
        return "", ""


class SmtpSink:
    """A threaded capture-only SMTP relay. Stop with .shutdown()."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 use_ssl: bool = True, certdir: Path | None = None):
        self.host = host
        self.requested_port = port
        self.use_ssl = use_ssl
        self.certdir = Path(certdir) if certdir else Path(tempfile.mkdtemp(prefix="smtpsink_"))
        self.certdir.mkdir(parents=True, exist_ok=True)
        self.captured: list[dict] = []          # [{"raw": bytes, "from": str, "to": [str], "body": str}]
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.port = 0
        self._ssl_ctx: ssl.SSLContext | None = None

    # -- lifecycle -------------------------------------------------------- #
    def start(self) -> "SmtpSink":
        if self.use_ssl:
            certfile, keyfile = _self_signed_cert(self.certdir)
            if not certfile:
                # No openssl → degrade to plain so the demo still runs.
                self.use_ssl = False
            else:
                self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self._ssl_ctx.load_cert_chain(certfile, keyfile)
                self._ssl_ctx.check_hostname = False
                self._ssl_ctx.verify_mode = ssl.CERT_NONE

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.requested_port))
        self._sock.listen(8)
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self

    def shutdown(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=3)

    # -- accept loop ------------------------------------------------------ #
    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            t.start()

    def _handle(self, raw_conn: socket.socket) -> None:
        conn: socket.socket | ssl.SSLSocket = raw_conn
        try:
            if self.use_ssl and self._ssl_ctx is not None:
                # implicit TLS — wrap immediately on accept
                conn = self._ssl_ctx.wrap_socket(raw_conn, server_side=True)
            conn.settimeout(10)
            self._session(conn)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # -- one SMTP session ------------------------------------------------- #
    def _session(self, conn) -> None:
        def send(line: str) -> None:
            conn.sendall((line + "\r\n").encode())

        # Persistent read buffer shared by recv() and recv_data(). `nonlocal`
        # keeps the closures mutating the same binding instead of shadowing it.
        _rbuf: bytearray = bytearray()

        def recv() -> str:
            nonlocal _rbuf
            while b"\r\n" not in _rbuf and b"\n" not in _rbuf:
                chunk = conn.recv(4096)
                if not chunk:
                    if _rbuf:
                        out = bytes(_rbuf); _rbuf = bytearray()
                        return out.decode("utf-8", "replace")
                    return ""
                _rbuf += chunk
            # prefer \r\n, fall back to \n (smtplib's data() mixes line endings)
            idx = _rbuf.find(b"\r\n")
            sep = 2
            if idx < 0:
                idx = _rbuf.find(b"\n"); sep = 1
            line = bytes(_rbuf[:idx])
            del _rbuf[: idx + sep]
            return line.decode("utf-8", "replace")

        def recv_data() -> bytes:
            """Read the DATA body until a line containing only '.', binary-safe.

            Handles both \\r\\n and \\n line endings (smtplib.data sends the
            message with \\n separators). Undoes dot-stuffing. Returns raw body
            bytes (lines joined by \\r\\n).
            """
            nonlocal _rbuf
            lines: list[bytes] = []
            while True:
                # ensure at least one complete line is in _rbuf
                while b"\r\n" not in _rbuf and b"\n" not in _rbuf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    _rbuf += chunk
                idx = _rbuf.find(b"\r\n"); sep = 2
                if idx < 0:
                    idx = _rbuf.find(b"\n"); sep = 1
                if idx < 0:
                    # partial line at EOF
                    if _rbuf:
                        lines.append(bytes(_rbuf)); _rbuf = bytearray()
                    break
                ln = bytes(_rbuf[:idx])
                del _rbuf[: idx + sep]
                if ln == b".":
                    break
                lines.append(ln[1:] if ln.startswith(b"..") else ln)
            return b"\r\n".join(lines)

        send("220 smtp.sink.local ESMTP capture-sink")
        mail_from = None
        rcpt_to: list[str] = []
        while True:
            line = recv()
            if not line:
                return
            line = line.rstrip("\r\n")
            upper = line.upper()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                if self.use_ssl:
                    send("250-smtp.sink.local")
                    send("250-AUTH PLAIN LOGIN")
                    send("250 SIZE 10000000")
                else:
                    send("250-smtp.sink.local")
                    send("250-STARTTLS")
                    send("250-AUTH PLAIN LOGIN")
                    send("250 SIZE 10000000")
            elif upper.startswith("STARTTLS"):
                send("220 Ready to start TLS")
                # upgrade to TLS using a server-side context
                nonlocal_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                _cert, _key = _self_signed_cert(self.certdir)
                nonlocal_ctx.load_cert_chain(_cert, _key)
                nonlocal_ctx.check_hostname = False
                nonlocal_ctx.verify_mode = ssl.CERT_NONE
                conn = nonlocal_ctx.wrap_socket(conn, server_side=True)
                conn.settimeout(10)
            elif upper.startswith("AUTH"):
                # accept-all: always return 235 regardless of mechanism/creds.
                # The three shapes smtplib emits:
                #   AUTH PLAIN <b64-blob>   -> creds inline, reply 235 now
                #   AUTH PLAIN              -> creds on next line; send 334, eat it
                #   AUTH LOGIN              -> challenge-response; 334/334/235
                parts = line.split(" ")
                mechanism = parts[1].upper() if len(parts) > 1 else ""
                inline = len(parts) > 2 and parts[2].strip() != ""
                if inline:
                    pass  # already have the blob; just succeed
                elif mechanism == "LOGIN":
                    send("334 " + base64.b64encode(b"Username:").decode()); recv()
                    send("334 " + base64.b64encode(b"Password:").decode()); recv()
                else:  # bare "AUTH PLAIN" with no inline blob
                    send("334 "); recv()
                send("235 Authentication successful")
            elif upper.startswith("MAIL FROM"):
                mail_from = line.split(":", 1)[-1].strip().strip("<>")
                send("250 OK")
            elif upper.startswith("RCPT TO"):
                rcpt_to.append(line.split(":", 1)[-1].strip().strip("<>"))
                send("250 OK")
            elif upper == "DATA":
                send("354 Start mail input")
                raw = recv_data()
                try:
                    self._store(raw, mail_from, rcpt_to)
                except Exception:
                    import traceback as _tb
                    _tb.print_exc()
                send("250 OK message accepted")
                mail_from, rcpt_to = None, []
            elif upper == "QUIT":
                send("221 Bye")
                return
            elif upper == "RSET":
                mail_from, rcpt_to = None, []
                send("250 OK")
            elif upper == "NOOP":
                send("250 OK")
            else:
                send("250 OK")

    def _store(self, raw: bytes, mail_from: str | None, rcpt_to: list[str]) -> None:
        msg = message_from_bytes(raw)
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ("text/plain", "text/html"):
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode("utf-8", "replace")
        else:
            payload = msg.get_payload(decode=True)
            body = payload.decode("utf-8", "replace") if payload else msg.get_payload("")
        # also keep the full raw (headers + body) so secret-in-subject is caught
        with self._lock:
            self.captured.append({
                "raw": raw,
                "from": mail_from,
                "to": list(rcpt_to),
                "subject": msg.get("Subject", ""),
                "body": body,
                "raw_text": raw.decode("utf-8", "replace"),
            })

    # -- query ------------------------------------------------------------ #
    def captured_blobs(self) -> list[str]:
        """Concatenated raw_text+body of every captured message (for scanning)."""
        with self._lock:
            return [f"{c['raw_text']}\n{c['body']}" for c in self.captured]

    def drain(self) -> list[dict]:
        with self._lock:
            out = list(self.captured)
            self.captured.clear()
            return out


def wait_for_capture(sink: SmtpSink, timeout: float = 5.0) -> list[dict]:
    """Block until at least one message is captured or timeout elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        with sink._lock:
            if sink.captured:
                break
        time.sleep(0.05)
    return sink.drain()


__all__ = ["SmtpSink", "wait_for_capture"]
