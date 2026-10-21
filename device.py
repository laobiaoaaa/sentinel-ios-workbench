# SPDX-License-Identifier: MIT
"""Bounded SSH access to a user-configured iOS device.

Credentials are read only from the environment and never included in public state.
Host keys are verified before authentication; first connect records the key in data_dir.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import datetime as dt
import fcntl
import hashlib
import hmac
import io
import os
from pathlib import Path
import plistlib
import posixpath
import re
import select
import shlex
import shutil
import socket
import stat
import tempfile
import threading
import time
from typing import Callable, Iterator
from xml.parsers.expat import ExpatError

import paramiko


class DeviceError(RuntimeError):
    """A credential-free, user-facing SSH error."""


_HOSTS_LOCK = threading.Lock()
_TIMEOUT = 8.0
_FORWARD_CANCEL_TIMEOUT = 2.0
_MAX_FILE = 128 * 1024 * 1024
_MAX_TREE = 512 * 1024 * 1024
_TOOLS = "id uname sysctl launchctl ps frida-server frida-ps dpkg plutil tar tcpdump curl openssl"
_INFO_COMMAND = (
    "PATH=/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin:"
    "/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin; export PATH; "
    "printf '__MODEL__\\n'; sysctl -n hw.machine 2>/dev/null; "
    "printf '__ARCH__\\n'; uname -m 2>/dev/null; "
    "printf '__UID__\\n'; id -u 2>/dev/null; "
    "printf '__UNAME__\\n'; uname -srm 2>/dev/null; "
    "printf '__LAYOUT__\\n'; "
    "if [ -d /var/jb ]; then printf 'rootless\\n'; "
    "elif [ -d /Library/MobileSubstrate ] || [ -x /usr/bin/dpkg ] || [ -d /etc/apt ]; "
    "then printf 'rootful\\n'; else printf 'unknown\\n'; fi; "
    "printf '__TOOLS__\\n'; "
    f"for tool in {_TOOLS}; do p=$(command -v \"$tool\" 2>/dev/null); "
    "[ -z \"$p\" ] || printf '%s=%s\\n' \"$tool\" \"$p\"; done; :"
)
_FRIDA_PATHS = (
    "/var/jb/usr/sbin/frida-server", "/var/jb/usr/bin/frida-server",
    "/usr/sbin/frida-server", "/usr/bin/frida-server",
    "/usr/local/bin/frida-server", "/var/jb/usr/local/bin/frida-server",
)


def _env(name: str, default: str = "") -> str:
    return os.environ.get("PLUGIN_" + name, default)


def _fingerprint(key: paramiko.PKey) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _remote_path(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 4096:
        raise DeviceError("An absolute remote path is required")
    if "\x00" in value or ".." in value.split("/"):
        raise DeviceError("Invalid remote path")
    return posixpath.normpath(value)


def _entry_name(value: str) -> bool:
    return isinstance(value, str) and bool(value) and value not in (".", "..") and "/" not in value and "\x00" not in value and len(value) <= 255


def _limit(value: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
        raise DeviceError("Invalid transfer or output limit")
    return value


class _Tunnel:
    """Owns listener, workers, sockets and SSH channels for one forwarding scope."""

    def __init__(self, transport: paramiko.Transport):
        self.transport = transport
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.close_lock = threading.Lock()
        self.closed = False
        self.endpoints: set = set()
        self.threads: set[threading.Thread] = set()
        self.listener: socket.socket | None = None
        self.remote_port: int | None = None

    def add(self, endpoint) -> bool:
        with self.lock:
            if self.stop.is_set():
                endpoint.close()
                return False
            self.endpoints.add(endpoint)
        return True

    def launch(self, target, *args) -> bool:
        def run():
            try:
                target(*args)
            finally:
                with self.lock:
                    self.threads.discard(threading.current_thread())
        with self.lock:
            if self.stop.is_set() or len(self.threads) >= 65:
                return False
            worker = threading.Thread(target=run, daemon=True, name="ios-ssh-forward")
            self.threads.add(worker)
            worker.start()
        return True

    def bridge(self, left, right):
        if not self.add(right):
            left.close()
            with self.lock:
                self.endpoints.discard(left)
            return
        try:
            left.settimeout(2)
            right.settimeout(2)
            sources = [left, right]
            while sources and not self.stop.is_set() and self.transport.is_active():
                ready, _, _ = select.select(sources, [], [], 0.25)
                for source in ready:
                    target = right if source is left else left
                    data = source.recv(65536)
                    if data:
                        target.sendall(data)
                    else:
                        sources.remove(source)
                        if isinstance(target, paramiko.Channel):
                            target.shutdown_write()
                        else:
                            target.shutdown(socket.SHUT_WR)
        except (OSError, EOFError, paramiko.SSHException, ValueError):
            pass
        finally:
            for endpoint in (left, right):
                with contextlib.suppress(Exception):
                    endpoint.close()
                with self.lock:
                    self.endpoints.discard(endpoint)

    def close(self):
        with self.close_lock:
            if self.closed:
                return
            self.closed = True
            self.stop.set()
            if self.listener is not None:
                with contextlib.suppress(OSError):
                    self.listener.close()
            with self.lock:
                endpoints = list(self.endpoints)
                threads = list(self.threads)
                self.endpoints.clear()
            # Local cleanup must not depend on a reply from the remote SSH host.
            for endpoint in endpoints:
                with contextlib.suppress(Exception):
                    endpoint.close()
            if self.remote_port is not None and self.transport.is_active():
                done = threading.Event()

                def cancel():
                    try:
                        self.transport.cancel_port_forward("127.0.0.1", self.remote_port)
                    except Exception:
                        pass
                    finally:
                        done.set()

                # Paramiko's cancel uses a global request with no reply deadline.
                # Closing this captured transport releases a stalled request and
                # marks it offline without touching a replacement connection.
                worker = threading.Thread(target=cancel, daemon=True, name="ios-ssh-cancel-forward")
                try:
                    worker.start()
                    if not done.wait(_FORWARD_CANCEL_TIMEOUT):
                        self.transport.close()
                    worker.join(0.5)
                except Exception:
                    with contextlib.suppress(Exception):
                        self.transport.close()
            deadline = time.monotonic() + 1.0
            for thread in threads:
                if thread is not threading.current_thread():
                    thread.join(max(0, deadline - time.monotonic()))


class Device:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self._lock = threading.RLock()
        self._connect_lock = threading.Lock()
        self._reverse_lock = threading.Lock()
        self._transport: paramiko.Transport | None = None
        self._channels: set = set()
        self._tunnels: set[_Tunnel] = set()
        self._identity: tuple[str, int, str] | None = None
        self._info: dict = {}
        self._capabilities: dict = {}
        self._last_seen: str | None = None
        self._host_fingerprint: str | None = None
        self._apps_cache: tuple[float, list[dict]] | None = None
        self._epoch = 0
        self._reverse_tunnel: _Tunnel | None = None

    def _config(self, require_host=True) -> tuple[str, int, str, str]:
        host, user = _env("SSH_HOST").strip(), _env("SSH_USER", "root").strip()
        if (require_host and not host) or len(host) > 255 or any(ord(c) < 33 for c in host):
            raise DeviceError("Set a valid PLUGIN_SSH_HOST")
        if not user or len(user) > 128 or any(ord(c) < 32 for c in user):
            raise DeviceError("Set a valid PLUGIN_SSH_USER")
        try:
            port = int(_env("SSH_PORT", "22"))
            if not 1 <= port <= 65535:
                raise ValueError()
        except ValueError:
            raise DeviceError("Set a valid PLUGIN_SSH_PORT") from None
        pin = _env("SSH_FINGERPRINT").strip().rstrip("=")
        if pin and not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", pin):
            raise DeviceError("SSH fingerprint must use SHA256 format")
        return host, port, user, pin

    def _verify_key(self, host: str, port: int, key: paramiko.PKey, pin: str, *, remember=True) -> bool:
        fingerprint = _fingerprint(key)
        if pin and not hmac.compare_digest(fingerprint, pin):
            raise DeviceError("SSH host fingerprint does not match the configured pin")
        identity = f"[{host}]:{port}"
        path = self.data_dir / "known_hosts"

        def load_and_check():
            keys = paramiko.HostKeys()
            if path.exists():
                if path.stat().st_size > 1024 * 1024:
                    raise DeviceError("SSH known_hosts file exceeds the size limit")
                keys.load(str(path))
            existing = keys.lookup(identity)
            if existing and not any(hmac.compare_digest(item.asbytes(), key.asbytes()) for item in existing.values()):
                raise DeviceError("SSH host key changed; verify the device before updating known_hosts")
            return keys, bool(existing)

        if not remember:
            with _HOSTS_LOCK:
                _, known = load_and_check()
            return known or bool(pin)
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        with _HOSTS_LOCK, (self.data_dir / "known_hosts.lock").open("a+b") as lock_file:
            os.chmod(lock_file.name, 0o600)
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            keys, known = load_and_check()
            if known:
                return True
            keys.add(identity, key.get_name(), key)
            fd, temporary = tempfile.mkstemp(prefix=".known_hosts-", dir=self.data_dir)
            os.close(fd)
            try:
                keys.save(temporary)
                os.chmod(temporary, 0o600)
                with open(temporary, "rb") as saved:
                    os.fsync(saved.fileno())
                os.replace(temporary, path)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary)
            return True

    def _handshake(self, host, port, pin, *, remember=True) -> tuple[paramiko.Transport, bool]:
        transport = None
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=_TIMEOUT)
            transport = paramiko.Transport(sock)
            transport.banner_timeout = _TIMEOUT
            transport.auth_timeout = _TIMEOUT
            transport.channel_timeout = _TIMEOUT
            transport.start_client(timeout=_TIMEOUT)
            trusted = self._verify_key(host, port, transport.get_remote_server_key(), pin, remember=remember)
            return transport, trusted
        except Exception as error:
            if transport is not None:
                with contextlib.suppress(Exception):
                    transport.close()
            elif sock is not None:
                sock.close()
            if isinstance(error, DeviceError):
                raise error from None
            raise DeviceError("SSH handshake failed or the host key could not be verified") from None

    def probe(self) -> dict:
        host, port, _, pin = self._config()
        transport, trusted = self._handshake(host, port, pin, remember=False)
        try:
            key = transport.get_remote_server_key()
            return {"host": host, "port": port, "fingerprint": _fingerprint(key),
                    "algorithm": key.get_name(), "trusted": trusted, "authenticated": False}
        finally:
            with contextlib.suppress(Exception):
                transport.close()

    @staticmethod
    def _private_key(pem: str, passphrase: str) -> paramiko.PKey:
        if len(pem) > 65536:
            raise DeviceError("SSH private key exceeds the size limit")
        for kind in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
            try:
                return kind.from_private_key(io.StringIO(pem), password=passphrase or None)
            except (paramiko.SSHException, ValueError):
                continue
        raise DeviceError("SSH private key is invalid or its passphrase is incorrect")

    def connect(self) -> dict:
        with self._connect_lock:
            host, port, user, pin = self._config()
            self.disconnect()
            with self._lock:
                epoch = self._epoch
            transport, _ = self._handshake(host, port, pin)
            try:
                with self._lock:
                    if self._epoch != epoch:
                        raise DeviceError("SSH connection was cancelled")
                    # Make in-progress authentication cancellable by disconnect().
                    self._transport = transport
                    self._identity = host, port, user
                    self._host_fingerprint = _fingerprint(transport.get_remote_server_key())
                    self._apps_cache = None
                    self._info, self._capabilities = {}, {}
                pem, password = _env("SSH_PRIVATE_KEY"), _env("SSH_PASSWORD")
                if pem:
                    try:
                        key = self._private_key(pem, _env("SSH_KEY_PASSPHRASE"))
                    except DeviceError:
                        # An explicitly configured password can recover from an
                        # unusable saved key; absent a password, keep the key error.
                        if not password:
                            raise
                    else:
                        try:
                            transport.auth_publickey(user, key)
                        except paramiko.AuthenticationException:
                            if not password:
                                raise
                if not transport.is_authenticated() and password:
                    transport.auth_password(user, password, fallback=False)
                if not transport.is_authenticated():
                    raise DeviceError("SSH authentication requires a valid password or private key")
                transport.set_keepalive(15)
                with self._lock:
                    if self._epoch != epoch or transport is not self._transport:
                        raise DeviceError("SSH connection was cancelled")
                info, capabilities = self._collect_info()
                with self._lock:
                    if transport is not self._transport:
                        raise DeviceError("SSH connection was cancelled")
                    self._info, self._capabilities = info, capabilities
                    self._last_seen = _now()
                return self.status()
            except Exception as error:
                with contextlib.suppress(Exception):
                    transport.close()
                self.disconnect()
                if isinstance(error, DeviceError):
                    raise error from None
                if isinstance(error, paramiko.AuthenticationException):
                    raise DeviceError("SSH authentication failed") from None
                raise DeviceError("SSH connection or device information discovery failed") from None

    def _require_transport(self) -> paramiko.Transport:
        with self._lock:
            transport = self._transport
            if transport is None or not transport.is_active() or not transport.is_authenticated():
                raise DeviceError("SSH device is not connected")
            return transport

    def status(self, refresh: bool = False) -> dict:
        if refresh:
            self.exec(":", timeout=5, max_bytes=1024)
        with self._lock:
            transport = self._transport
            online = bool(transport and transport.is_active() and transport.is_authenticated())
            host, port, user = self._identity or self._config(require_host=False)[:3]
            return {"online": online, "host": host, "port": port, "username": user,
                    "fingerprint": self._host_fingerprint, "info": copy.deepcopy(self._info),
                    "capabilities": copy.deepcopy(self._capabilities), "last_seen": self._last_seen}

    def disconnect(self) -> dict:
        with self._lock:
            self._epoch += 1
            transport, self._transport = self._transport, None
            channels, self._channels = list(self._channels), set()
            tunnels, self._tunnels = list(self._tunnels), set()
            self._apps_cache = None
            self._reverse_tunnel = None
        # Closing transport first interrupts any pending SSH global/channel request.
        if transport:
            with contextlib.suppress(Exception):
                transport.close()
        for channel in channels:
            with contextlib.suppress(Exception):
                channel.close()
        for tunnel in tunnels:
            tunnel.close()
        return self.status()

    def exec(self, command: str, timeout: float = 20, max_bytes: int = 1048576) -> tuple[int, bytes, bytes]:
        """Internal command runner. Drains both streams before reading exit status."""
        _limit(max_bytes, 16 * 1024 * 1024)
        if not isinstance(command, str) or not command or len(command) > 65536 or "\x00" in command:
            raise DeviceError("Invalid SSH command")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 600:
            raise DeviceError("Invalid SSH command timeout")
        transport = self._require_transport()
        channel = None
        deadline = time.monotonic() + timeout
        try:
            channel = transport.open_session(timeout=min(timeout, _TIMEOUT))
            channel.settimeout(min(timeout, _TIMEOUT))
            with self._lock:
                if transport is not self._transport:
                    raise DeviceError("SSH device disconnected")
                self._channels.add(channel)
            # Paramiko's exec request waits for an acknowledgement without a deadline.
            # A timer closes this channel to bound that wait as well as output reads.
            timer = threading.Timer(max(0, deadline - time.monotonic()), channel.close)
            timer.daemon = True
            timer.start()
            try:
                channel.exec_command(command)
                stdout, stderr = bytearray(), bytearray()
                while True:
                    if time.monotonic() >= deadline:
                        raise DeviceError("SSH command timed out")
                    received = False
                    for ready, receive, output in ((channel.recv_ready, channel.recv, stdout),
                                                   (channel.recv_stderr_ready, channel.recv_stderr, stderr)):
                        if ready():
                            chunk = receive(min(65536, max_bytes + 1 - len(stdout) - len(stderr)))
                            output.extend(chunk)
                            received = bool(chunk) or received
                            if len(stdout) + len(stderr) > max_bytes:
                                raise DeviceError("SSH command output exceeds the size limit")
                    if channel.exit_status_ready() and (channel.eof_received or channel.closed) and not channel.recv_ready() and not channel.recv_stderr_ready():
                        code = channel.recv_exit_status()
                        if code == -1:
                            raise DeviceError("SSH command closed without an exit status")
                        with self._lock:
                            if transport is self._transport:
                                self._last_seen = _now()
                        return code, bytes(stdout), bytes(stderr)
                    if not transport.is_active():
                        raise DeviceError("SSH connection was lost")
                    if not received:
                        time.sleep(0.01)
            finally:
                timer.cancel()
        except Exception as error:
            if isinstance(error, DeviceError):
                raise error from None
            if time.monotonic() >= deadline:
                raise DeviceError("SSH command timed out") from None
            raise DeviceError("SSH command failed") from None
        finally:
            if channel is not None:
                with contextlib.suppress(Exception):
                    channel.close()
                with self._lock:
                    self._channels.discard(channel)

    @contextlib.contextmanager
    def _sftp(self):
        transport = self._require_transport()
        channel = None
        client = None
        timer = None
        try:
            channel = transport.open_session(timeout=_TIMEOUT)
            channel.settimeout(_TIMEOUT)
            with self._lock:
                if transport is not self._transport:
                    raise DeviceError("SSH device disconnected")
                self._channels.add(channel)
            timer = threading.Timer(_TIMEOUT, channel.close)
            timer.daemon = True
            timer.start()
            channel.invoke_subsystem("sftp")
            client = paramiko.SFTPClient(channel)
            timer.cancel()
            yield client
        except Exception as error:
            if isinstance(error, DeviceError):
                raise error from None
            raise DeviceError("SFTP operation failed or timed out") from None
        finally:
            if timer:
                timer.cancel()
            if client:
                with contextlib.suppress(Exception):
                    client.close()
            if channel:
                with contextlib.suppress(Exception):
                    channel.close()
                with self._lock:
                    self._channels.discard(channel)

    @staticmethod
    def _read_file(sftp, remote: str, maximum: int, deadline: float) -> bytes:
        attrs = sftp.stat(remote)
        if not stat.S_ISREG(attrs.st_mode or 0) or attrs.st_size is None or not 0 <= attrs.st_size <= maximum:
            raise DeviceError("Remote file is not regular or exceeds the size limit")
        chunks, count = [], 0
        with sftp.open(remote, "rb") as source:
            while True:
                if time.monotonic() >= deadline:
                    raise DeviceError("SFTP read timed out")
                chunk = source.read(min(65536, maximum + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                if count > maximum:
                    raise DeviceError("Remote file exceeds the size limit")
                chunks.append(chunk)
        if count != attrs.st_size:
            raise DeviceError("Remote file changed during transfer")
        return b"".join(chunks)

    def _collect_info(self) -> tuple[dict, dict]:
        code, output, _ = self.exec(_INFO_COMMAND, timeout=15, max_bytes=65536)
        if code:
            raise DeviceError("Device information command failed")
        sections, current = {}, None
        for line in output.decode("utf-8", "replace").splitlines():
            if re.fullmatch(r"__[A-Z]+__", line):
                current = line.strip("_")
                sections[current] = []
            elif current:
                sections[current].append(line[:2048])
        first = lambda key: next(iter(sections.get(key, [])), "")
        tools_found = {}
        for line in sections.get("TOOLS", []):
            name, sep, path = line.partition("=")
            if sep and name in _TOOLS.split() and path.startswith("/"):
                tools_found[name] = path
        uid = first("UID")
        info = {"model": first("MODEL"), "architecture": first("ARCH"),
                "uid": int(uid) if uid.isdecimal() else None, "uname": first("UNAME"),
                "jailbreak_layout": first("LAYOUT") or "unknown",
                "system_version": None, "build_version": None, "product_name": None}
        candidates = []
        sftp_available = False
        try:
            with self._sftp() as sftp:
                sftp_available = True
                try:
                    raw = self._read_file(sftp, "/System/Library/CoreServices/SystemVersion.plist", 1024 * 1024, time.monotonic() + 10)
                    version = plistlib.loads(raw)
                    if isinstance(version, dict):
                        for dest, source in (("system_version", "ProductVersion"), ("build_version", "ProductBuildVersion"), ("product_name", "ProductName")):
                            value = version.get(source)
                            info[dest] = value[:256] if isinstance(value, str) else None
                except (OSError, ValueError, ExpatError, plistlib.InvalidFileException, DeviceError):
                    pass
                paths = list(dict.fromkeys([tools_found.get("frida-server")] + list(_FRIDA_PATHS)))
                for path in paths:
                    if not path:
                        continue
                    try:
                        attrs = sftp.stat(path)
                    except OSError:
                        continue
                    if stat.S_ISREG(attrs.st_mode or 0) and attrs.st_mode & 0o111:
                        candidates.append({"path": path, "version": None})
        except DeviceError:
            pass
        for candidate in candidates:
            try:
                code, output, _ = self.exec(shlex.quote(candidate["path"]) + " --version", timeout=5, max_bytes=4096)
                version = output.decode("utf-8", "replace").strip()
                if code == 0 and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.]+)?", version):
                    candidate["version"] = version
            except DeviceError:
                continue
        info["is_ios"] = info["product_name"] in ("iPhone OS", "iOS", "iPadOS")
        frida = {"available": bool(candidates), "candidates": candidates,
                 "server_path": candidates[0]["path"] if candidates else None,
                 "server_version": candidates[0]["version"] if candidates else None}
        return info, {"ssh_exec": True, "sftp": sftp_available, "local_forward": "unverified",
                      "remote_forward": "unverified", "tools": tools_found, "frida": frida}

    def apps(self) -> list[dict]:
        transport = self._require_transport()
        with self._lock:
            if self._apps_cache and time.monotonic() - self._apps_cache[0] < 60:
                return copy.deepcopy(self._apps_cache[1])
        result, seen = [], set()
        deadline, scanned = time.monotonic() + 45, 0
        with self._sftp() as sftp:
            pending = [("/Applications", 0), ("/var/jb/Applications", 0), ("/var/containers/Bundle/Application", 1)]
            while pending and scanned < 4000 and len(result) < 1000:
                root, depth = pending.pop(0)
                try:
                    # No outstanding READDIR response while stat/open runs below.
                    # Paramiko listdir_iter reads packets directly; prefetching here
                    # lets a nested synchronous request consume a directory reply.
                    entries = sftp.listdir_iter(root, read_aheads=1)
                    try:
                        for item in entries:
                            if time.monotonic() >= deadline:
                                raise DeviceError("Application enumeration timed out")
                            scanned += 1
                            if scanned > 4000 or len(result) >= 1000:
                                break
                            if not _entry_name(item.filename):
                                continue
                            path = posixpath.join(root, item.filename)
                            mode = item.st_mode or 0
                            if item.filename.endswith(".app") and (stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                                try:
                                    if stat.S_ISLNK(mode):
                                        # Rootless launch entries can be aliases. Expose
                                        # the actual app directory; tree copying itself
                                        # still refuses and skips symbolic links.
                                        path = _remote_path(sftp.normalize(path))
                                        if not stat.S_ISDIR(sftp.lstat(path).st_mode or 0):
                                            continue
                                    app = plistlib.loads(self._read_file(sftp, path + "/Info.plist", 1024 * 1024, deadline))
                                except (OSError, ValueError, ExpatError, plistlib.InvalidFileException, DeviceError):
                                    continue
                                if not isinstance(app, dict):
                                    continue
                                bundle = app.get("CFBundleIdentifier")
                                if not isinstance(bundle, str) or not bundle or len(bundle) > 512 or bundle in seen:
                                    continue
                                executable = app.get("CFBundleExecutable", "")
                                name = app.get("CFBundleDisplayName") or app.get("CFBundleName") or item.filename[:-4]
                                seen.add(bundle)
                                result.append({"bundle_id": bundle, "name": str(name)[:512], "path": path,
                                               "executable": executable if _entry_name(executable) else ""})
                            elif depth and stat.S_ISDIR(mode):
                                pending.append((path, depth - 1))
                    finally:
                        entries.close()
                except (FileNotFoundError, PermissionError):
                    continue
        result.sort(key=lambda item: (item["name"].casefold(), item["bundle_id"]))
        with self._lock:
            if transport is not self._transport:
                raise DeviceError("SSH connection was lost")
            self._apps_cache = time.monotonic(), result
            self._last_seen = _now()
        return copy.deepcopy(result)

    @staticmethod
    def _copy_file(sftp, remote, local, maximum, deadline, cancel=None) -> tuple[int, str]:
        attrs = sftp.lstat(remote)
        if not stat.S_ISREG(attrs.st_mode or 0) or attrs.st_size is None or not 0 <= attrs.st_size <= maximum:
            raise DeviceError("Remote file is not regular or exceeds the size limit")
        count, digest = 0, hashlib.sha256()
        with sftp.open(remote, "rb") as source, open(local, "xb") as target:
            while True:
                if cancel and cancel():
                    raise DeviceError("Transfer cancelled")
                if time.monotonic() >= deadline:
                    raise DeviceError("SFTP download timed out")
                chunk = source.read(min(65536, maximum + 1 - count))
                if not chunk:
                    break
                count += len(chunk)
                if count > maximum:
                    raise DeviceError("Remote file exceeds the size limit")
                target.write(chunk)
                digest.update(chunk)
        if count != attrs.st_size:
            raise DeviceError("Remote file changed during transfer")
        # Preserve executable bits for copied application binaries and ZIP output,
        # without carrying setuid/setgid/sticky flags onto the local filesystem.
        os.chmod(local, attrs.st_mode & 0o777)
        return count, digest.hexdigest()

    def download(self, remote: str, local: Path, max_bytes: int = 64 * 1024 * 1024) -> dict:
        remote, maximum = _remote_path(remote), _limit(max_bytes, _MAX_TREE)
        local = Path(local)
        local.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".ios-download-", dir=local.parent)
        os.close(fd)
        os.unlink(temporary)
        try:
            with self._sftp() as sftp:
                count, digest = self._copy_file(sftp, remote, temporary, maximum, time.monotonic() + 120)
            os.replace(temporary, local)
            with self._lock:
                self._last_seen = _now()
            return {"path": str(local), "remote_path": remote, "bytes": count, "sha256": digest}
        except Exception as error:
            if isinstance(error, DeviceError):
                raise error from None
            raise DeviceError("SFTP download failed") from None
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)

    def download_tree(self, remote_dir: str, local_dir: Path, max_total_bytes: int = _MAX_TREE,
                      cancel: Callable[[], bool] | None = None) -> dict:
        """Copy a bounded directory tree without following remote symbolic links."""
        remote_dir, maximum = _remote_path(remote_dir), _limit(max_total_bytes, _MAX_TREE)
        local_dir = Path(local_dir)
        if local_dir.is_symlink() or (local_dir.exists() and (not local_dir.is_dir() or any(local_dir.iterdir()))):
            raise DeviceError("Download destination must be absent or an empty directory")
        local_dir.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".ios-tree-", dir=local_dir.parent))
        total = files = entries_seen = 0
        skipped = []
        deadline = time.monotonic() + 600
        cancellation_error = None

        def check_cancel():
            nonlocal cancellation_error
            try:
                return bool(cancel and cancel())
            except Exception as error:
                # Task runners may signal cancellation by raising their own type.
                # Preserve that type so a cancelled task is not marked failed.
                cancellation_error = error
                raise

        try:
            if check_cancel():
                raise DeviceError("Transfer cancelled")
            with self._sftp() as sftp:
                if not stat.S_ISDIR(sftp.lstat(remote_dir).st_mode or 0):
                    raise DeviceError("Remote application path is not a directory")
                pending = [(remote_dir, staging)]
                while pending:
                    source_dir, dest_dir = pending.pop()
                    iterator = sftp.listdir_iter(source_dir, read_aheads=1)
                    try:
                        for item in iterator:
                            if check_cancel():
                                raise DeviceError("Transfer cancelled")
                            if time.monotonic() >= deadline:
                                raise DeviceError("SFTP download timed out")
                            entries_seen += 1
                            if entries_seen > 10000:
                                raise DeviceError("Application tree exceeds 10000 entries")
                            if not _entry_name(item.filename):
                                raise DeviceError("Invalid filename in application tree")
                            source = posixpath.join(source_dir, item.filename)
                            dest = dest_dir / item.filename
                            attrs = sftp.lstat(source)
                            mode = attrs.st_mode or 0
                            if stat.S_ISLNK(mode):
                                skipped.append(posixpath.relpath(source, remote_dir))
                            elif stat.S_ISDIR(mode):
                                dest.mkdir()
                                pending.append((source, dest))
                            elif stat.S_ISREG(mode):
                                remaining = min(_MAX_FILE, maximum - total)
                                if attrs.st_size is None or attrs.st_size > remaining:
                                    raise DeviceError("Application tree exceeds the transfer size limit")
                                count, _ = self._copy_file(sftp, source, dest, remaining, deadline, check_cancel)
                                total += count
                                files += 1
                    finally:
                        iterator.close()
            if check_cancel():
                raise DeviceError("Transfer cancelled")
            os.replace(staging, local_dir)
            with self._lock:
                self._last_seen = _now()
            return {"path": str(local_dir), "remote_path": remote_dir, "bytes": total,
                    "files": files, "skipped_symlinks": skipped}
        except Exception as error:
            if cancellation_error is not None:
                raise cancellation_error from None
            if isinstance(error, DeviceError):
                raise error from None
            raise DeviceError("SFTP application download failed") from None
        finally:
            if staging.exists():
                shutil.rmtree(staging)

    @contextlib.contextmanager
    def forward(self, remote_host: str = "127.0.0.1", remote_port: int = 27042) -> Iterator[int]:
        if not isinstance(remote_host, str) or not remote_host or len(remote_host) > 255 or any(ord(c) < 33 for c in remote_host):
            raise DeviceError("Invalid forwarding host")
        _limit(remote_port, 65535)
        transport = self._require_transport()
        tunnel = _Tunnel(transport)
        yielded = False
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tunnel.listener = listener
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            listener.settimeout(0.25)
            with self._lock:
                if transport is not self._transport:
                    raise DeviceError("SSH device disconnected")
                self._tunnels.add(tunnel)

            def client_worker(client, address):
                channel = None
                try:
                    channel = transport.open_channel("direct-tcpip", (remote_host, remote_port), address, timeout=_TIMEOUT)
                    tunnel.bridge(client, channel)
                except (OSError, EOFError, paramiko.SSHException):
                    client.close()
                    if channel:
                        channel.close()
                    with tunnel.lock:
                        tunnel.endpoints.discard(client)

            def accept():
                while not tunnel.stop.is_set() and transport.is_active():
                    try:
                        client, address = listener.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not tunnel.add(client) or not tunnel.launch(client_worker, client, address):
                        client.close()
                        with tunnel.lock:
                            tunnel.endpoints.discard(client)
            tunnel.launch(accept)
            yielded = True
            yield listener.getsockname()[1]
        except Exception as error:
            if yielded:
                raise
            if isinstance(error, DeviceError):
                raise error from None
            raise DeviceError("SSH local forwarding failed") from None
        finally:
            tunnel.close()
            with self._lock:
                self._tunnels.discard(tunnel)

    @contextlib.contextmanager
    def reverse(self, local_port: int, remote_port: int = 0) -> Iterator[int]:
        _limit(local_port, 65535)
        if isinstance(remote_port, bool) or not isinstance(remote_port, int) or not 0 <= remote_port <= 65535:
            raise DeviceError("Invalid reverse forwarding port")
        transport = self._require_transport()
        tunnel = _Tunnel(transport)
        outcome, done = {}, threading.Event()
        yielded = False
        try:
            with self._lock:
                if transport is not self._transport:
                    raise DeviceError("SSH device disconnected")
                if self._reverse_tunnel is not None:
                    raise DeviceError("An SSH reverse forwarding scope is already active")
                self._reverse_tunnel = tunnel
                self._tunnels.add(tunnel)

            def serve(channel):
                sock = None
                try:
                    sock = socket.create_connection(("127.0.0.1", local_port), timeout=_TIMEOUT)
                    tunnel.bridge(channel, sock)
                except OSError:
                    channel.close()
                    if sock:
                        sock.close()
                    with tunnel.lock:
                        tunnel.endpoints.discard(channel)

            def handler(channel, origin, server):
                if not tunnel.add(channel) or not tunnel.launch(serve, channel):
                    channel.close()
                    with tunnel.lock:
                        tunnel.endpoints.discard(channel)

            def request():
                try:
                    with self._reverse_lock:
                        if tunnel.stop.is_set():
                            return
                        port = transport.request_port_forward("127.0.0.1", remote_port, handler=handler)
                        tunnel.remote_port = port
                        outcome["port"] = port
                        if tunnel.stop.is_set():
                            transport.cancel_port_forward("127.0.0.1", port)
                except Exception:
                    outcome["failed"] = True
                finally:
                    done.set()
            tunnel.launch(request)
            if not done.wait(_TIMEOUT):
                self.disconnect()
                raise DeviceError("SSH remote forwarding request timed out")
            if outcome.get("failed") or not outcome.get("port"):
                raise DeviceError("SSH remote forwarding is unavailable")
            yielded = True
            yield outcome["port"]
        except Exception as error:
            if yielded:
                raise
            if isinstance(error, DeviceError):
                raise error from None
            raise DeviceError("SSH remote forwarding failed") from None
        finally:
            tunnel.close()
            with self._lock:
                self._tunnels.discard(tunnel)
                if self._reverse_tunnel is tunnel:
                    self._reverse_tunnel = None
