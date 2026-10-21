"""Real loopback mitmdump + SSH reverse + HTTP origin integration tests.

Run with: python -m unittest discover -s tests -p test_proxy.py -v
Requires the project's httpx/paramiko dependencies and mitmdump on PATH. Missing
dependencies produce explicit skips. No iOS device or external host is contacted.
The Popen observer retains real subprocess objects; it never replaces execution.
"""
from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
MISSING = [name for name in ('paramiko', 'httpx') if importlib.util.find_spec(name) is None]
if not shutil.which('mitmdump'):
    MISSING.append('mitmdump executable on PATH')
if not MISSING:
    import paramiko
    from device import Device, _fingerprint
    from jobs import Jobs, atomic_json
    import operations
    from test_device import _SSHFixture

LARGE_BODY = b'loopback-streamed-fixture-' * 90_000  # > 1 MiB streaming threshold.


class _OriginHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *unused):
        pass

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def _respond(self):
        count = int(self.headers.get('Content-Length', '0'))
        if count > 4 * 1024 * 1024:
            self.send_error(413)
            return
        request = {'method': self.command, 'path': self.path,
                   'headers': dict(self.headers.items()), 'body': self.rfile.read(count)}
        self.server.received.put(request)
        if self.path.startswith('/large'):
            body, content_type = LARGE_BODY, 'application/octet-stream'
        else:
            body = json.dumps({'method': self.command, 'path': self.path,
                               'body': request['body'].decode('utf-8'),
                               'x_fixture_rule': self.headers.get('X-Fixture-Rule')}).encode()
            content_type = 'application/json'
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Set-Cookie', 'fixture-response-cookie=secret')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


@unittest.skipIf(bool(MISSING), 'real proxy integration dependencies missing: ' + ', '.join(MISSING))
class ProxyIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host_key = paramiko.RSAKey.generate(2048)

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='.proxy-integration-', dir=ROOT / 'tests')
        self.root = Path(self.scratch.name)
        self.remote = self.root / 'remote'
        system = self.remote / 'System/Library/CoreServices/SystemVersion.plist'
        system.parent.mkdir(parents=True)
        system.write_bytes(plistlib.dumps({'ProductName': 'iPhone OS', 'ProductVersion': 'fixture-only',
                                          'ProductBuildVersion': 'LOCAL-TEST'}))
        self.fixture = _SSHFixture(self.remote, self.host_key)
        self.env = patch.dict(os.environ, {
            'PLUGIN_SSH_HOST': '127.0.0.1', 'PLUGIN_SSH_PORT': str(self.fixture.port),
            'PLUGIN_SSH_USER': 'root', 'PLUGIN_SSH_PASSWORD': 'fixture-secret',
            'PLUGIN_SSH_PRIVATE_KEY': '', 'PLUGIN_SSH_KEY_PASSPHRASE': '',
            'PLUGIN_SSH_FINGERPRINT': _fingerprint(self.host_key),
        })
        self.env.start()
        self.device = Device(self.root / 'ssh-data')
        self.jobs = Jobs(self.root / 'data', self.root / 'artifacts')
        self.origin = ThreadingHTTPServer(('127.0.0.1', 0), _OriginHandler)
        self.origin.daemon_threads = True
        self.origin.received = queue.Queue()
        self.origin_thread = threading.Thread(target=self.origin.serve_forever, daemon=True)
        self.origin_thread.start()
        self.processes = []
        self.job_ids = []
        real_popen = subprocess.Popen

        def observe_popen(*args, **kwargs):
            # Observe the real process/port, with exactly the production arguments.
            process = real_popen(*args, **kwargs)
            self.processes.append(process)
            return process
        self.popen_observer = patch.object(operations.subprocess, 'Popen', observe_popen)
        self.popen_observer.start()
        self.cleaned = False
        self.addCleanup(self._cleanup)
        self.device.connect()

    def tearDown(self):
        self._cleanup()

    def _cleanup(self):
        if self.cleaned:
            return
        self.cleaned = True
        try:
            for job_id in self.job_ids:
                self.jobs.cancel(job_id)
            deadline = time.monotonic() + 12
            while self.jobs.busy() and time.monotonic() < deadline:
                time.sleep(.05)
            self.device.disconnect()
            # Failure-only cleanup: assertions check production termination first.
            for process in self.processes:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
            self.fixture.close()
            self.origin.shutdown()
            self.origin.server_close()
            self.origin_thread.join(timeout=2)
        finally:
            self.popen_observer.stop()
            self.env.stop()
            self.scratch.cleanup()

    def wait_state(self, job_id, predicate, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.jobs.get(job_id)
            if predicate(state):
                return state
            if state['status'] in ('failed', 'cancelled', 'completed', 'interrupted'):
                self.fail('job ended before expected state: ' + json.dumps(state, ensure_ascii=False))
            time.sleep(.05)
        self.fail('timed out waiting for proxy state: ' + json.dumps(self.jobs.get(job_id), ensure_ascii=False))

    def start_proxy(self, duration=60, wait_ready=True):
        state = self.jobs.start('proxy', lambda job: operations.proxy(job, self.device, {'duration': duration}), 'proxy')
        self.job_ids.append(state['job_id'])
        if wait_ready:
            state = self.wait_state(state['job_id'], lambda item: item['stage'] == 'capturing')
            self.assertTrue(self.processes, 'operations.proxy did not launch mitmdump')
            self.assertIsNone(self.processes[-1].poll(), 'actual mitmdump already exited')
            self.assertEqual(state['connection']['device_proxy_host'], '127.0.0.1')
        return state

    @staticmethod
    def local_proxy_port(process):
        return int(process.args[process.args.index('--listen-port') + 1])

    @staticmethod
    def is_listening(port):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                return True
        except OSError:
            return False

    def assert_port_closed(self, port):
        deadline = time.monotonic() + 3
        while self.is_listening(port) and time.monotonic() < deadline:
            time.sleep(.05)
        self.assertFalse(self.is_listening(port), f'listener remains open on localhost:{port}')

    def assert_cleaned(self, job_id, remote_port=None):
        self.assertTrue(self.processes)
        process = self.processes[-1]
        self.assertIsNotNone(process.poll(), 'production did not terminate mitmdump')
        self.assert_port_closed(self.local_proxy_port(process))
        if remote_port is not None:
            self.assert_port_closed(remote_port)
        self.assertIsNone(self.device._reverse_tunnel)
        self.assertFalse(self.device._tunnels)
        self.assertEqual([item.name for item in (self.jobs.data / job_id).iterdir()], ['state.json'])
        self.assertEqual(self.device.exec(':'), (0, b'', b''), 'cleanup broke the underlying SSH connection')

    def request(self, remote_port, path, body=b'', method='POST'):
        # Absolute-form HTTP explicitly targets the remote SSH listener. No
        # urllib/no_proxy shortcuts can accidentally contact the origin directly.
        connection = http.client.HTTPConnection('127.0.0.1', remote_port, timeout=15)
        try:
            url = f'http://127.0.0.1:{self.origin.server_port}{path}'
            connection.request(method, url, body=body, headers={
                'Host': f'127.0.0.1:{self.origin.server_port}', 'Connection': 'close',
                'Authorization': 'Bearer fixture-auth-token', 'Cookie': 'fixture-request-cookie=secret',
                'Content-Type': 'text/plain',
            })
            response = connection.getresponse()
            data = response.read()
            self.assertEqual(response.status, 200)
            return data
        finally:
            connection.close()

    def read_flows(self, job_id, minimum=1):
        path = self.jobs.artifacts / job_id / 'http-flows.jsonl'
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            records = []
            if path.exists():
                for line in path.read_text().splitlines():
                    try:
                        records.append(json.loads(line))
                    except ValueError:  # A concurrent write has not finished yet.
                        pass
            if len(records) >= minimum:
                return records
            time.sleep(.05)
        self.fail(f'mitmdump did not persist {minimum} real HTTP flow(s)')

    def test_reverse_capture_rule_mutation_clear_streaming_and_cancel_cleanup(self):
        ready = self.start_proxy()
        job_id = ready['job_id']
        remote_port = ready['connection']['device_proxy_port']
        self.assertNotEqual(remote_port, self.local_proxy_port(self.processes[-1]))
        self.assertTrue(self.fixture.listeners, 'no SSH reverse listener was created')

        baseline = json.loads(self.request(remote_port, '/baseline', b'original-request'))
        self.assertEqual(baseline['body'], 'original-request')
        original = self.origin.received.get(timeout=2)
        self.assertEqual(original['path'], '/baseline')
        self.assertEqual(original['body'], b'original-request')
        first = self.read_flows(job_id)[0]
        self.assertEqual(base64.b64decode(first['request_body_base64']), b'original-request')
        request_headers = {k.lower(): v for k, v in first['request_headers'].items()}
        response_headers = {k.lower(): v for k, v in first['response_headers'].items()}
        self.assertEqual(request_headers['authorization'], '[redacted]')
        self.assertEqual(request_headers['cookie'], '[redacted]')
        self.assertEqual(response_headers['set-cookie'], '[redacted]')
        self.assertTrue(first['request_body_available'])
        self.assertFalse(first['request_body_truncated'])
        self.assertFalse(first['modified_request'])

        # Use the same atomic rules-file interface as ios_proxy_rules_set.
        atomic_json(self.jobs.data / job_id / 'rules.json', [{
            'url_contains': '/mutate', 'request_headers': {'X-Fixture-Rule': 'applied'},
            'request_body': 'mutated-request', 'response_body': 'mutated-response',
        }])
        self.assertEqual(self.request(remote_port, '/mutate', b'before-mutation'), b'mutated-response')
        mutated = self.origin.received.get(timeout=2)
        self.assertEqual(mutated['body'], b'mutated-request')
        self.assertEqual({k.lower(): v for k, v in mutated['headers'].items()}['x-fixture-rule'], 'applied')
        second = self.read_flows(job_id, 2)[1]
        self.assertTrue(second['modified_request'])
        self.assertTrue(second['modified_response'])
        self.assertEqual(base64.b64decode(second['request_body_base64']), b'mutated-request')
        self.assertEqual(base64.b64decode(second['response_body_base64']), b'mutated-response')

        atomic_json(self.jobs.data / job_id / 'rules.json', [])
        cleared = json.loads(self.request(remote_port, '/mutate', b'restored-request'))
        self.assertEqual(cleared['body'], 'restored-request')
        self.assertIsNone(cleared['x_fixture_rule'])
        self.origin.received.get(timeout=2)
        third = self.read_flows(job_id, 3)[2]
        self.assertFalse(third['modified_request'])
        self.assertFalse(third['modified_response'])

        atomic_json(self.jobs.data / job_id / 'rules.json', [{
            'url_contains': '/large', 'response_body': 'must-not-replace-streamed-body',
        }])
        received = self.request(remote_port, '/large', method='GET')
        self.assertEqual(hashlib.sha256(received).digest(), hashlib.sha256(LARGE_BODY).digest())
        self.origin.received.get(timeout=2)
        fourth = self.read_flows(job_id, 4)[3]
        self.assertFalse(fourth['response_body_available'])
        self.assertTrue(fourth['response_body_truncated'])
        self.assertEqual(fourth['response_body_base64'], '')
        self.assertFalse(fourth['modified_response'])
        self.assertEqual(fourth['skipped_response_mutation'], 'streamed body unavailable')

        self.jobs.cancel(job_id)
        finished = self.wait_state(job_id, lambda item: item['status'] == 'cancelled', timeout=12)
        self.assertIn(job_id + '/http-flows.jsonl', finished['artifacts'])
        self.assertIn(job_id + '/proxy-ca-cert.pem', finished['artifacts'])
        self.assert_cleaned(job_id, remote_port)
        for path in (self.jobs.artifacts / job_id).iterdir():
            self.assertLess(path.stat().st_size, 50 * 1024 * 1024)
            self.assertNotIn(b'fixture-secret', path.read_bytes(), 'SSH configuration secret leaked into artifacts')
        self.assertTrue((self.jobs.artifacts / job_id / 'proxy-ca-cert.pem').read_bytes().startswith(b'-----BEGIN CERTIFICATE-----'))

    def test_natural_completion_reports_real_flow_count_and_closes_both_ports(self):
        ready = self.start_proxy(duration=2)
        job_id, remote_port = ready['job_id'], ready['connection']['device_proxy_port']
        body = json.loads(self.request(remote_port, '/completed', b'completed-body'))
        self.assertEqual(body['body'], 'completed-body')
        self.read_flows(job_id)
        finished = self.wait_state(job_id, lambda item: item['status'] == 'completed', timeout=12)
        self.assertEqual(finished['result']['captured_flows'], 1)
        self.assert_cleaned(job_id, remote_port)

    def test_reverse_rejection_stops_real_mitmdump_and_cleans_work(self):
        self.fixture.allow_reverse = False
        state = self.start_proxy(wait_ready=False)
        finished = self.wait_state(state['job_id'], lambda item: item['status'] == 'failed')
        self.assertIn('forwarding', finished['error'])
        self.assertNotIn('connection', finished)
        self.assert_cleaned(state['job_id'])


if __name__ == '__main__':
    unittest.main()
