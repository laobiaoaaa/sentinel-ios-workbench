"""Real loopback HTTP tests for API checks, independent of MCP/SSH imports.

Run with a Python environment containing httpx:
    python -m unittest discover -s tests -p 'test_api.py' -v

These exercise production operations.api_check and production artifact writes.
They do not import server, jsonschema, paramiko, or mock the HTTP transport.
"""
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from jobs import Job, Jobs
from operations import api_check


@contextlib.contextmanager
def target_server(respond):
    """Record bytes received by a real target and send caller-defined responses."""
    observations = []
    lock = threading.Lock()

    class Target(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *unused):
            pass

        def handle_request(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            observation = {
                'method': self.command,
                'path': self.path,
                'headers': {key.lower(): value for key, value in self.headers.items()},
                'body': body,
            }
            with lock:
                observations.append(observation)
                index = len(observations)
            status, headers, content = respond(observation, index)
            self.send_response(status)
            self.send_header('Content-Length', str(len(content)))
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            try:
                # Large responses are genuinely streamed over a socket. A client
                # enforcing a size limit is allowed to close before the tail.
                for offset in range(0, len(content), 65536):
                    self.wfile.write(content[offset:offset + 65536])
            except (BrokenPipeError, ConnectionResetError):
                pass

        do_GET = handle_request
        do_POST = handle_request

    server = ThreadingHTTPServer(('127.0.0.1', 0), Target)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', observations
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        if thread.is_alive():
            raise AssertionError('Loopback HTTP target failed to shut down')


class ApiTests(unittest.TestCase):
    def setUp(self):
        # Keep test data in the source workspace, rather than in a system temp
        # directory. Both the task state and actual report files are removed.
        self.temp = tempfile.TemporaryDirectory(prefix='.api-test-', dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manager = Jobs(self.root / 'data', self.root / 'artifacts')

    def run_check(self, url, **arguments):
        job = Job(self.manager, 'api', 'api')
        result = api_check(job, {'url': url, **arguments})
        report = json.loads((job.out / 'api-comparison.json').read_text(encoding='utf-8'))
        self.assertEqual(report, result, 'persisted comparison must match the returned result')
        return result, job

    def test_three_identities_do_not_share_response_cookies_or_request_credentials(self):
        def respond(request, index):
            auth = request['headers'].get('authorization')
            status = {'Bearer identity-a-fixture': 200, 'Bearer identity-b-fixture': 403}.get(auth, 401)
            return status, {
                'Set-Cookie': f'from-response={index}; Path=/',
                'Authorization': 'response-credential-fixture',
            }, b'Controlled target response'

        with target_server(respond) as (url, requests):
            result, job = self.run_check(
                url + '/private', method='GET',
                headers={'Authorization': 'Bearer identity-a-fixture', 'Cookie': 'provided-cookie=a'},
                compare_headers={'Authorization': 'Bearer identity-b-fixture'},
            )

        self.assertEqual(len(requests), 3)
        self.assertEqual([r['headers'].get('authorization') for r in requests],
                         [None, 'Bearer identity-a-fixture', 'Bearer identity-b-fixture'])
        self.assertEqual([r['headers'].get('cookie') for r in requests],
                         [None, 'provided-cookie=a', None])
        self.assertEqual([sample['status'] for sample in result['samples']], [401, 200, 403])
        self.assertEqual([sample['identity'] for sample in result['samples']],
                         ['baseline', 'provided_identity', 'comparison_identity'])
        for sample in result['samples']:
            self.assertEqual(sample['response_headers']['set-cookie'], '[redacted]')
            self.assertEqual(sample['response_headers']['authorization'], '[redacted]')
        for report in job.out.glob('*.json'):
            raw = report.read_text(encoding='utf-8')
            self.assertNotIn('identity-a-fixture', raw)
            self.assertNotIn('identity-b-fixture', raw)
            self.assertNotIn('provided-cookie=a', raw)
            self.assertNotIn('response-credential-fixture', raw)

    def test_headerless_baseline_can_still_carry_url_and_body_identity_and_is_only_a_candidate(self):
        body = 'account_id=fixture-user&token=fixture-body-token'
        path = '/account?token=fixture-url-token'
        with target_server(lambda request, index: (200, {}, b'Account data fixture')) as (url, requests):
            result, _ = self.run_check(url + path, method='POST', body=body)

        self.assertEqual(len(requests), 1, 'empty identity headers must not create extra comparison requests')
        self.assertEqual(requests[0]['method'], 'POST')
        self.assertEqual(requests[0]['path'], path)
        self.assertEqual(requests[0]['body'], body.encode('utf-8'))
        self.assertNotIn('authorization', requests[0]['headers'])
        self.assertNotIn('cookie', requests[0]['headers'])
        self.assertEqual(result['samples'][0]['identity'], 'baseline')
        self.assertTrue(result['candidate_only'])
        self.assertFalse(result['confirmed_vulnerability'])
        self.assertIn('URL', result['interpretation'])
        self.assertIn('正文', result['interpretation'])
        self.assertIn('不能自动等同匿名', result['interpretation'])

    def test_post_protocol_headers_and_body_survive_all_three_independent_requests(self):
        body = '{"object":"fixture-owned-object"}'
        def respond(request,index):
            if request['headers'].get('content-type') != 'application/json':
                return 415, {}, b'wrong media type'
            return (200 if request['headers'].get('authorization') else 401), {}, b'fixture'
        with target_server(respond) as (url, requests):
            result,_ = self.run_check(url+'/json',method='POST',body=body,
                base_headers={'Content-Type':'application/json','Accept':'application/json'},
                headers={'Authorization':'Bearer fixture-a'},compare_headers={'Authorization':'Bearer fixture-b'})
        self.assertEqual([r['body'] for r in requests],[body.encode()]*3)
        self.assertEqual([r['headers']['content-type'] for r in requests],['application/json']*3)
        self.assertEqual([r['headers'].get('authorization') for r in requests],[None,'Bearer fixture-a','Bearer fixture-b'])
        self.assertEqual([s['status'] for s in result['samples']],[401,200,200])

    def test_baseline_credentials_are_not_mislabelled_anonymous_and_overrides_are_case_insensitive(self):
        with target_server(lambda request,index:(200,{},b'fixture')) as (url,requests):
            result,job=self.run_check(url,base_headers={'Authorization':'fixture-baseline','Content-Type':'text/plain'},
                headers={'authorization':'fixture-identity','content-type':'application/json'})
        self.assertEqual([r['headers']['authorization'] for r in requests],['fixture-baseline','fixture-identity'])
        self.assertEqual([r['headers']['content-type'] for r in requests],['text/plain','application/json'])
        self.assertEqual(result['samples'][0]['identity'],'baseline')
        self.assertIn('基线请求头',result['interpretation'])
        self.assertFalse(result['confirmed_vulnerability'])
        self.assertNotIn('fixture-baseline',(job.out/'api-comparison.json').read_text())

    def test_invalid_later_identity_is_rejected_before_the_baseline_request(self):
        with target_server(lambda request,index:(200,{},b'fixture')) as (url,requests):
            with self.assertRaisesRegex(ValueError,'请求头不允许换行'):
                self.run_check(url,compare_headers={'Authorization':'bad\nheader'})
        self.assertEqual(requests,[])

    def test_redirect_response_is_reported_without_requesting_the_destination(self):
        def respond(request, index):
            if request['path'] == '/redirect':
                return 302, {'Location': '/destination', 'Set-Cookie': 'redirect-session=fixture; Path=/'}, b'Redirect fixture'
            return 200, {}, b'This destination must not be requested'

        with target_server(respond) as (url, requests):
            result, _ = self.run_check(url + '/redirect', method='GET')

        self.assertEqual([r['path'] for r in requests], ['/redirect'])
        self.assertEqual(result['samples'][0]['status'], 302)
        self.assertEqual(result['samples'][0]['response_headers']['location'], '/destination')
        self.assertEqual(result['samples'][0]['body_preview'], 'Redirect fixture')
        self.assertFalse(result['confirmed_vulnerability'])

    def test_response_limit_distinguishes_exact_size_from_a_truncated_stream(self):
        limit = 1024 * 1024
        prefix = b'0123456789abcdef' * (limit // 16)
        oversized = prefix + b'not-in-the-sampled-prefix' * 4096

        def respond(request, index):
            return 200, {'Content-Type': 'application/octet-stream'}, prefix if request['path'] == '/exact' else oversized

        with target_server(respond) as (url, requests):
            exact, _ = self.run_check(url + '/exact')
            truncated, job = self.run_check(url + '/oversized')

        self.assertEqual([r['path'] for r in requests], ['/exact', '/oversized'])
        self.assertFalse(exact['samples'][0]['truncated'])
        sample = truncated['samples'][0]
        self.assertTrue(sample['truncated'])
        self.assertEqual(sample['bytes_sampled'], limit)
        self.assertEqual(sample['sha256'], hashlib.sha256(prefix).hexdigest())
        self.assertEqual(sample['body_preview'], prefix[:4096].decode('ascii'))
        self.assertNotIn('not-in-the-sampled-prefix', sample['body_preview'])
        self.assertLess((job.out / 'api-comparison.json').stat().st_size, 20000)
        self.assertFalse(truncated['confirmed_vulnerability'])


if __name__ == '__main__':
    unittest.main()
