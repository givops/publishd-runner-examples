"""Ephemeral OpenSSL PKI and RFC 4217 Explicit FTPS loopback test server."""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import socket
import ssl
import subprocess
import threading


def generate_pki(root: Path) -> dict[str, Path]:
    """Generate a test CA, valid 127.0.0.1/localhost cert, wrong-SAN cert, and untrusted CA."""
    root.mkdir(parents=True, exist_ok=True)

    def openssl(*args: str) -> None:
        subprocess.run(
            ["/usr/bin/openssl", *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def make_ca(prefix: str, cn: str) -> tuple[Path, Path]:
        key = root / f"{prefix}-key.pem"
        cert = root / f"{prefix}-cert.pem"
        openssl(
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-days", "2", "-subj", f"/CN={cn}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", str(key), "-out", str(cert),
        )
        return key, cert

    def make_leaf(prefix: str, cn: str, san: str, ca_key: Path, ca_cert: Path) -> tuple[Path, Path]:
        key = root / f"{prefix}-key.pem"
        csr = root / f"{prefix}.csr"
        cert = root / f"{prefix}-cert.pem"
        ext = root / f"{prefix}.ext"
        ext.write_text(
            f"subjectAltName={san}\nbasicConstraints=CA:FALSE\n"
            f"keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
            encoding="utf-8",
        )
        openssl(
            "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-subj", f"/CN={cn}", "-keyout", str(key), "-out", str(csr),
        )
        openssl(
            "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
            "-CAcreateserial", "-out", str(cert), "-days", "2", "-extfile", str(ext),
        )
        return key, cert

    ca_key, ca_cert = make_ca("ca", "Publishd Test CA")
    _, untrusted_ca_cert = make_ca("untrusted-ca", "Untrusted Test CA")
    server_key, server_cert = make_leaf("server", "127.0.0.1", "IP:127.0.0.1,DNS:localhost", ca_key, ca_cert)
    wrong_key, wrong_cert = make_leaf("wrong", "wrong.example.invalid", "DNS:wrong.example.invalid", ca_key, ca_cert)

    return {
        "ca_cert": ca_cert,
        "untrusted_ca_cert": untrusted_ca_cert,
        "server_key": server_key,
        "server_cert": server_cert,
        "wrong_key": wrong_key,
        "wrong_cert": wrong_cert,
    }


class LoopbackFtpsServer:
    """Thread-backed loopback Explicit FTPS server enforcing AUTH TLS + PROT P + TYPE I."""

    def __init__(self, root_dir: Path, certfile: Path, keyfile: Path,
                 username: str = "deployer", password: str = "fixture-secret-pass") -> None:
        self.root_dir = root_dir.resolve()
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.username = username
        self.password = password
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ssl_context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))

        self.connection_count = 0
        self.commands: list[str] = []
        self.renames: list[tuple[str, str]] = []
        self.fail_on_rnto = False
        self.drop_mid_stor = False
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._clients: list[threading.Thread] = []

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=5)
        for t in self._clients:
            t.join(timeout=2)

    def _serve(self) -> None:
        while not self._stop_event.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with self._lock:
                self.connection_count += 1
            t = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
            self._clients.append(t)
            t.start()

    def _resolve(self, cwd_rel: PurePosixPath, arg: str) -> tuple[PurePosixPath, Path]:
        candidate = PurePosixPath(arg) if arg.startswith("/") else cwd_rel / arg
        parts: list[str] = []
        for part in candidate.parts:
            if part in {"", "/", "."}:
                continue
            if part == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(part)
        rel = PurePosixPath("/", *parts)
        fs_path = (self.root_dir / "/".join(parts)).resolve() if parts else self.root_dir
        if not fs_path.is_relative_to(self.root_dir):
            raise ValueError("Path escapes root")
        return rel, fs_path

    def _handle_client(self, raw_conn: socket.socket) -> None:
        conn: socket.socket | ssl.SSLSocket = raw_conn
        conn.settimeout(5)
        pasv_sock: socket.socket | None = None
        cwd_rel = PurePosixPath("/")
        authed = False
        pending_user: str | None = None
        tls_control = False
        prot_p = False
        transfer_type = "A"
        rnfr_path: Path | None = None
        rnfr_rel: str | None = None

        def send(line: str) -> None:
            conn.sendall((line + "\r\n").encode("utf-8"))

        def recv_line() -> str | None:
            buf = bytearray()
            while True:
                chunk = conn.recv(1)
                if not chunk:
                    return None
                if chunk == b"\n":
                    return bytes(buf).rstrip(b"\r").decode("utf-8", errors="replace")
                buf.extend(chunk)
                if len(buf) > 8192:
                    raise ValueError("Command line too long")

        def open_data_conn() -> socket.socket | ssl.SSLSocket:
            nonlocal pasv_sock
            assert pasv_sock is not None
            listener = pasv_sock
            pasv_sock = None
            try:
                data_conn, _ = listener.accept()
            finally:
                listener.close()
            data_conn.settimeout(5)
            if prot_p:
                data_conn = self.ssl_context.wrap_socket(data_conn, server_side=True)
            return data_conn

        def close_pasv() -> None:
            nonlocal pasv_sock
            if pasv_sock is not None:
                try:
                    pasv_sock.close()
                except OSError:
                    pass
                pasv_sock = None

        try:
            send("220 Loopback FTPS fixture ready")
            while not self._stop_event.is_set():
                line = recv_line()
                if line is None:
                    break
                cmd, _, arg = line.partition(" ")
                upper = cmd.upper()
                with self._lock:
                    self.commands.append(upper)

                if upper == "AUTH":
                    if arg.upper() in {"TLS", "SSL"} and not tls_control:
                        send("234 AUTH TLS successful")
                        conn = self.ssl_context.wrap_socket(conn, server_side=True)
                        tls_control = True
                    else:
                        send("502 Unsupported AUTH")
                elif upper == "QUIT":
                    send("221 Goodbye")
                    break
                elif upper == "USER":
                    if not tls_control:
                        send("530 AUTH TLS required before authentication")
                    else:
                        pending_user = arg
                        send("331 Password required")
                elif upper == "PASS":
                    if not tls_control or pending_user is None:
                        send("503 Bad sequence of commands")
                    elif pending_user == self.username and arg == self.password:
                        authed = True
                        send("230 Login successful")
                    else:
                        send("530 Login incorrect")
                elif not authed:
                    send("530 Not logged in")
                elif upper == "PBSZ":
                    send("200 PBSZ 0 successful" if arg == "0" else "501 Invalid PBSZ")
                elif upper == "PROT":
                    if arg.upper() == "P":
                        prot_p = True
                        send("200 Protection level set to P")
                    elif arg.upper() == "C":
                        prot_p = False
                        send("200 Protection level set to C")
                    else:
                        send("536 Unsupported PROT level")
                elif upper == "TYPE":
                    mode = arg.upper()
                    if mode in {"I", "A"}:
                        transfer_type = mode
                        send(f"200 Type set to {mode}")
                    else:
                        send("504 Unsupported type")
                elif upper == "PWD":
                    send(f'257 "{cwd_rel}" is current directory')
                elif upper == "CWD":
                    try:
                        new_rel, new_fs = self._resolve(cwd_rel, arg or "/")
                        if not new_fs.is_dir():
                            send("550 Directory not found")
                        else:
                            cwd_rel = new_rel
                            send("250 Directory changed")
                    except Exception:
                        send("550 Invalid directory")
                elif upper == "MKD":
                    try:
                        new_rel, new_fs = self._resolve(cwd_rel, arg)
                        new_fs.mkdir(exist_ok=False)
                        send(f'257 "{new_rel}" created')
                    except Exception:
                        send("550 Could not create directory")
                elif upper == "PASV":
                    if not prot_p:
                        send("522 PROT P required before passive data connection")
                        continue
                    close_pasv()
                    pasv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    pasv_sock.bind(("127.0.0.1", 0))
                    pasv_sock.listen(1)
                    pasv_sock.settimeout(5)
                    port = pasv_sock.getsockname()[1]
                    send(f"227 Entering Passive Mode (127,0,0,1,{port >> 8},{port & 0xff})")
                elif upper == "NLST":
                    if pasv_sock is None or not prot_p:
                        close_pasv()
                        send("522 PROT P and PASV required")
                        continue
                    target_fs = self._resolve(cwd_rel, arg)[1] if arg else self._resolve(cwd_rel, ".")[1]
                    if not target_fs.exists():
                        close_pasv()
                        send("550 Path not found")
                        continue
                    names = sorted(p.name for p in target_fs.iterdir()) if target_fs.is_dir() else [target_fs.name]
                    send("150 Opening ASCII mode data connection for file list")
                    data_conn = open_data_conn()
                    try:
                        payload = ("\r\n".join(names) + ("\r\n" if names else "")).encode("utf-8")
                        if payload:
                            data_conn.sendall(payload)
                        if isinstance(data_conn, ssl.SSLSocket):
                            data_conn.unwrap()
                    finally:
                        data_conn.close()
                    send("226 Transfer complete")
                elif upper == "STOR":
                    if pasv_sock is None or not prot_p:
                        close_pasv()
                        send("522 PROT P and PASV required")
                        continue
                    if transfer_type != "I":
                        close_pasv()
                        send("504 Binary TYPE I required")
                        continue
                    target_rel, target_fs = self._resolve(cwd_rel, arg)
                    if not target_fs.parent.is_dir():
                        close_pasv()
                        send("550 Target directory missing")
                        continue
                    send("150 Opening binary mode data connection")
                    data_conn = open_data_conn()
                    received = bytearray()
                    dropped = False
                    try:
                        while True:
                            chunk = data_conn.recv(8192)
                            if not chunk:
                                break
                            received.extend(chunk)
                            if self.drop_mid_stor:
                                dropped = True
                                break
                        if dropped:
                            target_fs.write_bytes(bytes(received[: max(1, len(received) // 2)]))
                            data_conn.close()
                            break
                        target_fs.write_bytes(bytes(received))
                        if isinstance(data_conn, ssl.SSLSocket):
                            try:
                                data_conn.unwrap()
                            except (ssl.SSLError, OSError):
                                pass
                    finally:
                        data_conn.close()
                    send("226 Transfer complete")
                elif upper == "RETR":
                    if pasv_sock is None or not prot_p:
                        close_pasv()
                        send("522 PROT P and PASV required")
                        continue
                    if transfer_type != "I":
                        close_pasv()
                        send("504 Binary TYPE I required")
                        continue
                    _, target_fs = self._resolve(cwd_rel, arg)
                    if not target_fs.is_file():
                        close_pasv()
                        send("550 File not found")
                        continue
                    send("150 Opening binary mode data connection")
                    data_conn = open_data_conn()
                    try:
                        data_conn.sendall(target_fs.read_bytes())
                        if isinstance(data_conn, ssl.SSLSocket):
                            try:
                                data_conn.unwrap()
                            except (ssl.SSLError, OSError):
                                pass
                    finally:
                        data_conn.close()
                    send("226 Transfer complete")
                elif upper == "RNFR":
                    try:
                        rel, fs_path = self._resolve(cwd_rel, arg)
                        if not fs_path.exists():
                            send("550 Source not found")
                        else:
                            rnfr_path = fs_path
                            rnfr_rel = str(rel)
                            send("350 Ready for RNTO")
                    except Exception:
                        send("550 Invalid RNFR")
                elif upper == "RNTO":
                    if rnfr_path is None or rnfr_rel is None:
                        send("503 RNFR required first")
                        continue
                    src = rnfr_path
                    src_rel = rnfr_rel
                    rnfr_path = None
                    rnfr_rel = None
                    if self.fail_on_rnto:
                        send("550 Simulated RNTO failure")
                        continue
                    try:
                        dst_rel, dst_fs = self._resolve(cwd_rel, arg)
                        os.replace(src, dst_fs)
                        with self._lock:
                            self.renames.append((src_rel, str(dst_rel)))
                        send("250 Rename successful")
                    except Exception:
                        send("550 Rename failed")
                else:
                    send(f"502 Command {upper} not implemented")
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            close_pasv()
            try:
                conn.close()
            except OSError:
                pass
