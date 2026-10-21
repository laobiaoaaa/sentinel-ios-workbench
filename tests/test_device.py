# SPDX-License-Identifier: MIT
"""Real loopback Paramiko fixtures; these tests never access an iOS device."""
from __future__ import annotations

import contextlib
import errno
import io
import json
import os
from pathlib import Path
import plistlib
import select
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import paramiko

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from device import Device, DeviceError, _fingerprint, _INFO_COMMAND, _Tunnel


class _Files(paramiko.SFTPServerInterface):
    def __init__(self, server, *, root, **kwargs):
        super().__init__(server, **kwargs)
        self.root = root

    def path(self, remote):
        if not remote.startswith("/") or ".." in remote.split("/"):
            raise OSError(errno.EACCES, "denied")
        return self.root / remote.lstrip("/")

    def list_folder(self, path):
        try:
            result = []
            for entry in os.scandir(self.path(path)):
                attrs = paramiko.SFTPAttributes.from_stat(entry.stat(follow_symlinks=False))
                attrs.filename = entry.name
                result.append(attrs)
            return result
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    def stat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(self.path(path).stat())
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    def lstat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(self.path(path).lstat())
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    def canonicalize(self, path):
        try:
            return "/" + self.path(path).resolve().relative_to(self.root).as_posix()
        except (OSError, ValueError):
            return "/unavailable"

    def open(self, path, flags, attr):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            handle = paramiko.SFTPHandle(flags)
            handle.readfile = self.path(path).open("rb")
            return handle
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)


def _relay(left, right, stop):
    try:
        while not stop.is_set():
            ready, _, _ = select.select([left, right], [], [], 0.1)
            for source in ready:
                data = source.recv(65536)
                if not data:
                    return
                (right if source is left else left).sendall(data)
    except (OSError, EOFError, ValueError, paramiko.SSHException):
        pass
    finally:
        left.close()
        right.close()


class _Server(paramiko.ServerInterface):
    def __init__(self, fixture):
        self.fixture = fixture
        self.direct = {}
        self.transport = None
        self.reverse_sockets = {}

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        self.fixture.auth_attempts += 1
        return paramiko.AUTH_SUCCESSFUL if username == "root" and password == "fixture-secret" else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.fixture.auth_attempts += 1
        if self.fixture.user_key and key.asbytes() == self.fixture.user_key.asbytes():
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        if destination[0] != "127.0.0.1":
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        self.direct[chanid] = destination
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        command = command.decode()
        if command == "no-ack":
            self.fixture.stop.wait(2)
            return False
        self.fixture.commands.append(command)
        acknowledged = threading.Event()
        self.transport.exec_acknowledgements[channel.remote_chanid] = acknowledged

        def respond():
            try:
                # A real server acknowledges exec before it can finish the command.
                # Starting output directly inside this callback races that SSH reply.
                if not acknowledged.wait(2):
                    return
                if command == _INFO_COMMAND:
                    channel.sendall(b"__MODEL__\niPhoneFixture,1\n__ARCH__\narm64\n__UID__\n0\n__UNAME__\nDarwin fixture\n__LAYOUT__\nrootless\n__TOOLS__\nid=/usr/bin/id\nfrida-server=/var/jb/usr/sbin/frida-server\n")
                elif command.endswith("frida-server --version"):
                    channel.sendall(b"17.2.1\n")
                elif command == "streams":
                    channel.sendall_stderr(b"e" * 262144)
                    channel.sendall(b"o" * 262144)
                elif command == "flood":
                    for _ in range(1000):
                        channel.sendall_stderr(b"x" * 65536)
                elif command == "hold":
                    while not channel.closed and not self.fixture.stop.wait(0.05):
                        pass
                    return
                elif command == "early-status":
                    channel.send_exit_status(0)
                    time.sleep(0.05)
                    channel.sendall(b"after-status")
                    channel.shutdown_write()
                    return
                elif command == "fail":
                    channel.sendall_stderr(b"fixture command error")
                    channel.send_exit_status(7)
                    return
                elif command != ":":
                    channel.sendall(command.encode())
                channel.send_exit_status(0)
            except (OSError, EOFError, paramiko.SSHException):
                pass
            finally:
                channel.close()
        self.fixture.launch(respond)
        return True

    def check_port_forward_request(self, address, port):
        if address != "127.0.0.1" or not self.fixture.allow_reverse:
            return False
        listener = socket.socket()
        listener.bind((address, port))
        listener.listen(8)
        listener.settimeout(0.1)
        assigned = listener.getsockname()[1]
        self.reverse_sockets[assigned] = listener
        self.fixture.listeners.append(listener)

        def accept():
            while not self.fixture.stop.is_set():
                try:
                    client, origin = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    channel = self.transport.open_forwarded_tcpip_channel(origin, ("127.0.0.1", assigned))
                    self.fixture.launch(_relay, client, channel, self.fixture.stop)
                except (OSError, paramiko.SSHException):
                    client.close()
        self.fixture.launch(accept)
        return assigned

    def cancel_port_forward_request(self, address, port):
        listener = self.reverse_sockets.pop(port, None)
        if listener:
            listener.close()


class _FixtureTransport(paramiko.Transport):
    """Expose the actual SSH exec-success send to the fixture command worker."""

    def __init__(self, sock, fixture):
        self.fixture = fixture
        self.exec_acknowledgements = {}
        super().__init__(sock)

    def _parse_global_request(self, message):
        probe = paramiko.Message(message.asbytes())
        if probe.get_text() == "cancel-tcpip-forward" and not self.fixture.reply_to_cancel:
            probe.get_boolean()
            self.server_object.cancel_port_forward_request(probe.get_text(), probe.get_int())
            self.fixture.cancel_received.set()
            return  # Keep SSH active, but deliberately omit the global reply.
        return super()._parse_global_request(message)

    def _send_user_message(self, message):
        payload = message.asbytes()
        super()._send_user_message(message)
        if len(payload) >= 5 and payload[0] == 99:  # SSH_MSG_CHANNEL_SUCCESS
            remote_channel = int.from_bytes(payload[1:5], "big")
            event = self.exec_acknowledgements.pop(remote_channel, None)
            if event is not None:
                event.set()


class _SSHFixture:
    def __init__(self, root, key=None, port=0):
        self.root = root
        self.key = key or paramiko.RSAKey.generate(2048)
        self.user_key = None
        self.allow_reverse = True
        self.reply_to_cancel = True
        self.cancel_received = threading.Event()
        self.auth_attempts = 0
        self.commands = []
        self.stop = threading.Event()
        self.transports = []
        self.listeners = []
        self.threads = []
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", port))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(10)
        self.listener.settimeout(0.1)
        self.launch(self.accept)

    def launch(self, target, *args):
        worker = threading.Thread(target=target, args=args, daemon=True)
        self.threads.append(worker)
        worker.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.launch(self.serve, client)

    def serve(self, client):
        transport = _FixtureTransport(client, self)
        self.transports.append(transport)
        server = _Server(self)
        server.transport = transport
        transport.add_server_key(self.key)
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer, _Files, root=self.root)
        channels = []  # Transport's channel map contains weak references.
        try:
            transport.start_server(server=server)
            while transport.is_active() and not self.stop.is_set():
                channel = transport.accept(0.1)
                if channel is not None:
                    channels.append(channel)
                channels = [item for item in channels if not item.closed]
                if channel is not None and channel.chanid in server.direct:
                    try:
                        target = socket.create_connection(server.direct.pop(channel.chanid), timeout=2)
                        self.launch(_relay, channel, target, self.stop)
                    except OSError:
                        channel.close()
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            transport.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        for listener in self.listeners:
            listener.close()
        for transport in self.transports:
            transport.close()
        deadline = time.monotonic() + 2
        for thread in self.threads:
            thread.join(max(0, deadline - time.monotonic()))


class DeviceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host_key = paramiko.RSAKey.generate(2048)

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix=".device-test-", dir=Path(__file__).parent)
        self.root = Path(self.scratch.name)
        self.remote = self.root / "remote"
        self.remote.mkdir()
        self.write_remote("/System/Library/CoreServices/SystemVersion.plist", plistlib.dumps({
            "ProductName": "iPhone OS", "ProductVersion": "fixture-15", "ProductBuildVersion": "FIXTURE"}))
        self.write_remote("/var/jb/usr/sbin/frida-server", b"fixture binary")
        (self.remote / "var/jb/usr/sbin/frida-server").chmod(0o755)
        self.fixture = _SSHFixture(self.remote, self.host_key)
        self.env = patch.dict(os.environ, {"PLUGIN_SSH_HOST": "127.0.0.1", "PLUGIN_SSH_PORT": str(self.fixture.port),
                                         "PLUGIN_SSH_USER": "root", "PLUGIN_SSH_PASSWORD": "fixture-secret",
                                         "PLUGIN_SSH_PRIVATE_KEY": "", "PLUGIN_SSH_KEY_PASSPHRASE": "",
                                         "PLUGIN_SSH_FINGERPRINT": ""})
        self.env.start()
        self.device = Device(self.root / "data")

    def tearDown(self):
        self.device.disconnect()
        self.fixture.close()
        self.env.stop()
        self.scratch.cleanup()

    def write_remote(self, path, content):
        local = self.remote / path.lstrip("/")
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(content)

    def add_app(self, path, bundle, name):
        self.write_remote(path + "/Info.plist", plistlib.dumps({"CFBundleIdentifier": bundle,
            "CFBundleDisplayName": name, "CFBundleExecutable": "FixtureExecutable"}, fmt=plistlib.FMT_BINARY))
        self.write_remote(path + "/FixtureExecutable", b"fixture executable")
        (self.remote / (path + "/FixtureExecutable").lstrip("/")).chmod(0o755)

    def test_probe_is_handshake_only_and_never_records_tofu(self):
        result = self.device.probe()
        self.assertEqual(result["fingerprint"], _fingerprint(self.host_key))
        self.assertFalse(result["authenticated"])
        self.assertFalse(result["trusted"])
        self.assertEqual(self.fixture.auth_attempts, 0)
        self.assertEqual(self.fixture.commands, [])
        self.assertFalse((self.root / "data").exists())

    def test_first_connect_records_tofu_and_subsequent_probe_is_trusted(self):
        self.device.connect()
        path = self.root / "data/known_hosts"
        keys = paramiko.HostKeys(str(path))
        self.assertTrue(keys.check(f"[127.0.0.1]:{self.fixture.port}", self.host_key))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.device.disconnect()
        self.fixture.auth_attempts = 0
        self.assertTrue(self.device.probe()["trusted"])
        self.assertEqual(self.fixture.auth_attempts, 0)

    def test_probe_pin_match_is_trusted_but_does_not_write(self):
        os.environ["PLUGIN_SSH_FINGERPRINT"] = _fingerprint(self.host_key)
        self.assertTrue(self.device.probe()["trusted"])
        self.assertFalse((self.root / "data").exists())

    def test_pin_mismatch_rejected_before_authentication(self):
        os.environ["PLUGIN_SSH_FINGERPRINT"] = "SHA256:" + "A" * 43
        os.environ["PLUGIN_SSH_PRIVATE_KEY"] = "invalid-key-with-password-fallback"
        with self.assertRaisesRegex(DeviceError, "configured pin"):
            self.device.connect()
        with self.assertRaisesRegex(DeviceError, "configured pin"):
            self.device.probe()
        self.assertEqual(self.fixture.auth_attempts, 0)
        self.assertFalse((self.root / "data/known_hosts").exists())

    def test_changed_host_key_is_rejected_even_with_new_matching_pin(self):
        self.device.connect()
        self.device.disconnect()
        self.fixture.auth_attempts = 0
        new_key = paramiko.RSAKey.generate(2048)
        self.fixture.key = new_key
        os.environ["PLUGIN_SSH_FINGERPRINT"] = _fingerprint(new_key)
        with self.assertRaisesRegex(DeviceError, "host key changed"):
            self.device.connect()
        with self.assertRaisesRegex(DeviceError, "host key changed"):
            self.device.probe()
        self.assertEqual(self.fixture.auth_attempts, 0)

    def test_connect_reads_real_fixture_commands_and_sftp_plist(self):
        result = self.device.connect()
        self.assertTrue(result["online"])
        self.assertEqual(result["info"]["model"], "iPhoneFixture,1")
        self.assertEqual(result["info"]["system_version"], "fixture-15")
        self.assertEqual(result["info"]["uid"], 0)
        self.assertEqual(result["info"]["jailbreak_layout"], "rootless")
        self.assertEqual(result["capabilities"]["frida"]["candidates"], [{"path": "/var/jb/usr/sbin/frida-server", "version": "17.2.1"}])
        self.assertNotIn("fixture-secret", json.dumps(result))
        old = result["last_seen"]
        self.assertGreaterEqual(self.device.status(refresh=True)["last_seen"], old)
        result["info"]["model"] = "mutated"
        self.assertEqual(self.device.status()["info"]["model"], "iPhoneFixture,1")

    def test_private_key_authentication_without_password(self):
        key = paramiko.RSAKey.generate(2048)
        self.fixture.user_key = key
        buffer = io.StringIO()
        key.write_private_key(buffer, password="key-fixture-secret")
        os.environ.update(PLUGIN_SSH_PRIVATE_KEY=buffer.getvalue(), PLUGIN_SSH_PASSWORD="", PLUGIN_SSH_KEY_PASSPHRASE="key-fixture-secret")
        self.assertTrue(self.device.connect()["online"])
        self.assertNotIn("PRIVATE", repr(self.device.status()))

    def test_invalid_private_key_falls_back_to_explicit_password(self):
        os.environ["PLUGIN_SSH_PRIVATE_KEY"] = "invalid-private-key-do-not-log"
        result = self.device.connect()
        self.assertTrue(result["online"])
        self.assertEqual(self.fixture.auth_attempts, 1)
        self.assertNotIn("invalid-private-key", json.dumps(result))
        self.assertNotIn("fixture-secret", json.dumps(result))

    def test_wrong_private_key_passphrase_falls_back_to_explicit_password(self):
        key = paramiko.RSAKey.generate(2048)
        buffer = io.StringIO()
        key.write_private_key(buffer, password="correct-key-passphrase")
        os.environ.update(PLUGIN_SSH_PRIVATE_KEY=buffer.getvalue(),
                          PLUGIN_SSH_KEY_PASSPHRASE="wrong-key-passphrase-do-not-log")
        result = self.device.connect()
        self.assertTrue(result["online"])
        self.assertEqual(self.fixture.auth_attempts, 1)
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertNotIn("passphrase", json.dumps(result))

    def test_invalid_private_key_without_password_preserves_clean_key_error(self):
        os.environ.update(PLUGIN_SSH_PRIVATE_KEY="invalid-private-key-do-not-log",
                          PLUGIN_SSH_PASSWORD="", PLUGIN_SSH_KEY_PASSPHRASE="passphrase-do-not-log")
        with self.assertRaises(DeviceError) as caught:
            self.device.connect()
        self.assertEqual(str(caught.exception), "SSH private key is invalid or its passphrase is incorrect")
        self.assertNotIn("do-not-log", str(caught.exception))
        self.assertEqual(self.fixture.auth_attempts, 0)
        self.assertFalse(self.device.status()["online"])

    def test_invalid_private_key_and_wrong_password_fail_without_exposing_secrets(self):
        os.environ.update(PLUGIN_SSH_PRIVATE_KEY="invalid-private-key-do-not-log",
                          PLUGIN_SSH_PASSWORD="wrong-password-do-not-log",
                          PLUGIN_SSH_KEY_PASSPHRASE="passphrase-do-not-log")
        with self.assertRaises(DeviceError) as caught:
            self.device.connect()
        self.assertEqual(str(caught.exception), "SSH authentication failed")
        self.assertNotIn("do-not-log", str(caught.exception))
        self.assertEqual(self.fixture.auth_attempts, 1)
        self.assertFalse(self.device.status()["online"])

    def test_failed_authentication_does_not_expose_secret(self):
        os.environ["PLUGIN_SSH_PASSWORD"] = "wrong-secret-do-not-log"
        with self.assertRaises(DeviceError) as caught:
            self.device.connect()
        self.assertEqual(str(caught.exception), "SSH authentication failed")
        self.assertNotIn("wrong-secret", str(caught.exception))
        self.assertFalse(self.device.status()["online"])

    def test_only_plugin_prefixed_credentials_are_used(self):
        os.environ["PLUGIN_SSH_PASSWORD"] = ""
        os.environ["SSH_PASSWORD"] = "fixture-secret"
        with self.assertRaisesRegex(DeviceError, "requires a valid password"):
            self.device.connect()
        self.assertEqual(self.fixture.auth_attempts, 0)

    def test_exec_drains_both_streams_and_preserves_exit_code(self):
        self.device.connect()
        code, stdout, stderr = self.device.exec("streams")
        self.assertEqual((code, len(stdout), len(stderr)), (0, 262144, 262144))
        self.assertEqual(self.device.exec("fail"), (7, b"", b"fixture command error"))
        self.assertEqual(self.device.exec("early-status"), (0, b"after-status", b""))

    def test_output_limit_and_timeout_leave_connection_usable(self):
        self.device.connect()
        start = time.monotonic()
        with self.assertRaisesRegex(DeviceError, "size limit"):
            self.device.exec("flood", max_bytes=1024)
        with self.assertRaisesRegex(DeviceError, "timed out"):
            self.device.exec("hold", timeout=0.1)
        self.assertLess(time.monotonic() - start, 3)
        self.assertEqual(self.device.exec(":"), (0, b"", b""))

    def test_missing_exec_acknowledgement_has_a_deadline(self):
        self.device.connect()
        start = time.monotonic()
        with self.assertRaisesRegex(DeviceError, "timed out"):
            self.device.exec("no-ack", timeout=0.1)
        self.assertLess(time.monotonic() - start, 1)

    def test_apps_enumerate_rootless_and_container_paths_with_cache(self):
        self.add_app("/Applications/System.app", "fixture.system", "System")
        self.add_app("/var/jb/Applications/Jailbreak.app", "fixture.rootless", "Rootless")
        self.add_app("/var/containers/Bundle/Application/UUID/User.app", "fixture.user", "User")
        self.write_remote("/Applications/Bad.app/Info.plist", b"invalid plist")
        self.device.connect()
        apps = self.device.apps()
        self.assertEqual({item["bundle_id"] for item in apps}, {"fixture.system", "fixture.rootless", "fixture.user"})
        self.assertTrue(all(item["executable"] == "FixtureExecutable" for item in apps))
        self.add_app("/Applications/New.app", "fixture.new", "New")
        apps.clear()
        self.assertEqual(len(self.device.apps()), 3)

    def test_download_is_bounded_atomic_and_has_digest(self):
        self.write_remote("/sample", b"abcdef")
        self.device.connect()
        target = self.root / "sample-local"
        target.write_bytes(b"old")
        with self.assertRaisesRegex(DeviceError, "size limit"):
            self.device.download("/sample", target, max_bytes=5)
        self.assertEqual(target.read_bytes(), b"old")
        result = self.device.download("/sample", target, max_bytes=6)
        self.assertEqual(result["bytes"], 6)
        self.assertEqual(target.read_bytes(), b"abcdef")
        self.assertEqual(len(result["sha256"]), 64)
        self.assertFalse(list(self.root.glob(".ios-download-*")))

    def test_rootless_app_alias_returns_real_directory_for_download(self):
        self.add_app("/var/jb/Applications/Real.app", "fixture.alias", "Alias")
        (self.remote / "Applications").mkdir()
        (self.remote / "Applications/Alias.app").symlink_to("../var/jb/Applications/Real.app")
        self.device.connect()
        apps = self.device.apps()
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0]["path"], "/var/jb/Applications/Real.app")
        copied = self.device.download_tree(apps[0]["path"], self.root / "resolved-app")
        self.assertEqual(copied["files"], 2)
        self.assertEqual(stat.S_IMODE((self.root / "resolved-app/FixtureExecutable").stat().st_mode), 0o755)

    def test_download_preserves_permissions_without_privilege_flags(self):
        self.write_remote("/executable", b"fixture executable")
        (self.remote / "executable").chmod(0o6755)
        self.device.connect()
        target = self.root / "executable"
        self.device.download("/executable", target)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)

    def test_tree_skips_symlinks_and_rolls_back_oversize_or_cancel(self):
        self.add_app("/Applications/Tree.app", "fixture.tree", "Tree")
        self.write_remote("/Applications/Tree.app/sub/resource", b"resource")
        (self.remote / "Applications/Tree.app/link").symlink_to("sub/resource")
        self.device.connect()
        with self.assertRaisesRegex(DeviceError, "size limit"):
            self.device.download_tree("/Applications/Tree.app", self.root / "too-small", max_total_bytes=1)
        self.assertFalse((self.root / "too-small").exists())
        with self.assertRaisesRegex(DeviceError, "cancelled"):
            self.device.download_tree("/Applications/Tree.app", self.root / "cancelled", cancel=lambda: True)
        self.assertFalse((self.root / "cancelled").exists())
        target = self.root / "tree"
        target.mkdir()
        result = self.device.download_tree("/Applications/Tree.app", target)
        self.assertEqual(result["files"], 3)
        self.assertEqual(result["skipped_symlinks"], ["link"])
        self.assertEqual((target / "sub/resource").read_bytes(), b"resource")
        self.assertEqual(stat.S_IMODE((target / "FixtureExecutable").stat().st_mode), 0o755)
        self.assertFalse((target / "link").exists())
        self.assertFalse(list(self.root.glob(".ios-tree-*")))

    def test_tree_preserves_task_runner_cancellation_exception(self):
        class Cancelled(Exception):
            pass
        def cancel():
            raise Cancelled("cancel requested")
        self.add_app("/Applications/Tree.app", "fixture.tree", "Tree")
        self.device.connect()
        with self.assertRaisesRegex(Cancelled, "cancel requested"):
            self.device.download_tree("/Applications/Tree.app", self.root / "cancelled", cancel=cancel)
        self.assertFalse((self.root / "cancelled").exists())
        self.assertFalse(list(self.root.glob(".ios-tree-*")))

    @contextlib.contextmanager
    def echo_server(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        listener.settimeout(0.1)
        stop = threading.Event()
        clients = []

        def serve():
            while not stop.is_set():
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                clients.append(client)
                try:
                    client.settimeout(2)
                    while not stop.is_set():
                        data = client.recv(65536)
                        if not data:
                            break
                        client.sendall(data)
                except OSError:
                    pass
                finally:
                    client.close()
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            yield listener.getsockname()[1]
        finally:
            stop.set()
            listener.close()
            for client in clients:
                client.close()
            worker.join(2)

    def test_forward_uses_direct_tcpip_and_closes_scope(self):
        self.device.connect()
        with self.echo_server() as echo_port:
            with self.device.forward(remote_port=echo_port) as local_port:
                with socket.create_connection(("127.0.0.1", local_port), timeout=2) as client:
                    client.sendall(b"forwarded bytes")
                    self.assertEqual(client.recv(100), b"forwarded bytes")
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", local_port), timeout=0.2)

    def test_forward_preserves_the_callers_exception(self):
        self.device.connect()
        with self.assertRaisesRegex(ValueError, "consumer failure"):
            with self.device.forward():
                raise ValueError("consumer failure")

    def test_reverse_uses_remote_localhost_and_closes_scope(self):
        self.device.connect()
        with self.echo_server() as local_port:
            with self.device.reverse(local_port) as remote_port:
                with socket.create_connection(("127.0.0.1", remote_port), timeout=2) as client:
                    client.sendall(b"reverse bytes")
                    self.assertEqual(client.recv(100), b"reverse bytes")
                with self.assertRaisesRegex(DeviceError, "already active"):
                    with self.device.reverse(local_port):
                        pass
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                try:
                    sock = socket.create_connection(("127.0.0.1", remote_port), timeout=0.1)
                except OSError:
                    break
                sock.close()
                time.sleep(0.01)
            else:
                self.fail("remote forwarding listener remained open")

    def test_reverse_refusal_is_clean_and_disconnect_closes_active_tunnels(self):
        self.device.connect()
        self.fixture.allow_reverse = False
        with self.assertRaisesRegex(DeviceError, "unavailable"):
            with self.device.reverse(12345):
                pass
        with self.device.forward() as port:
            self.assertFalse(self.device.disconnect()["online"])
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", port), timeout=0.2)
        self.assertFalse(self.device._channels)
        self.assertFalse(self.device._tunnels)

    def test_reverse_missing_cancel_reply_finishes_and_marks_transport_offline(self):
        self.device.connect()
        transport = self.device._require_transport()
        self.fixture.reply_to_cancel = False
        scope = self.device.reverse(12345)
        scope.__enter__()
        errors = []

        def close_scope():
            try:
                scope.__exit__(None, None, None)
            except Exception as error:
                errors.append(error)

        with patch("device._FORWARD_CANCEL_TIMEOUT", 0.15):
            worker = threading.Thread(target=close_scope, daemon=True)
            worker.start()
            worker.join(2)
            timed_out = worker.is_alive()
            # Bound the test itself if the production cleanup regresses.
            if timed_out:
                transport.close()
                worker.join(1)
        self.assertFalse(timed_out, "reverse cleanup waited indefinitely for the SSH cancel reply")
        self.assertTrue(self.fixture.cancel_received.is_set())
        self.assertEqual(errors, [])
        self.assertFalse(self.device.status()["online"])
        self.assertFalse(self.device._tunnels)
        self.assertIsNone(self.device._reverse_tunnel)

    def test_disconnect_cancels_pending_exec(self):
        self.device.connect()
        errors = []
        def execute():
            try:
                self.device.exec("hold", timeout=10)
            except DeviceError as error:
                errors.append(str(error))
        worker = threading.Thread(target=execute)
        worker.start()
        deadline = time.monotonic() + 1
        while "hold" not in self.fixture.commands and time.monotonic() < deadline:
            time.sleep(0.01)
        self.device.disconnect()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertTrue(errors)

    def test_disconnect_during_handshake_cannot_reconnect_later(self):
        ready, proceed = threading.Event(), threading.Event()
        original = self.device._handshake
        errors = []
        def handshake(*args):
            transport = original(*args)
            ready.set()
            proceed.wait(2)
            return transport
        def connect():
            try:
                self.device.connect()
            except DeviceError as error:
                errors.append(str(error))
        with patch.object(self.device, "_handshake", side_effect=handshake):
            worker = threading.Thread(target=connect)
            worker.start()
            self.assertTrue(ready.wait(2))
            self.device.disconnect()
            proceed.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertFalse(self.device.status()["online"])
        self.assertEqual(errors, ["SSH connection was cancelled"])
        self.assertEqual(self.fixture.auth_attempts, 0)


class TunnelCleanupTests(unittest.TestCase):
    def test_local_cleanup_precedes_bounded_cancel_and_keeps_replacement_connection(self):
        class Endpoint:
            closed = False
            def close(self):
                self.closed = True

        endpoint, listener = Endpoint(), Endpoint()

        class Transport:
            def __init__(self):
                self.active = True
                self.closed = threading.Event()
                self.cancel_calls = 0
                self.local_was_closed = False
            def is_active(self):
                return self.active
            def is_authenticated(self):
                return self.active
            def close(self):
                self.active = False
                self.closed.set()
            def cancel_port_forward(self, address, port):
                self.cancel_calls += 1
                self.local_was_closed = endpoint.closed and listener.closed
                self.closed.wait(2)

        old, replacement = Transport(), Transport()
        device = Device(Path("unused-fixture-data"))
        device._transport = replacement
        device._identity = ("fixture.invalid", 22, "root")
        tunnel = _Tunnel(old)
        tunnel.listener, tunnel.remote_port = listener, 12345
        tunnel.add(endpoint)
        with patch("device._FORWARD_CANCEL_TIMEOUT", 0.05):
            tunnel.close()
            tunnel.close()
        self.assertTrue(old.local_was_closed)
        self.assertFalse(old.is_active())
        self.assertEqual(old.cancel_calls, 1)
        self.assertTrue(device.status()["online"])
        self.assertFalse(replacement.closed.is_set())
        self.assertFalse(tunnel.endpoints)


if __name__ == "__main__":
    unittest.main()
