"""mitmdump addon: bounded observations and explicit replacement rules."""
import base64
import json
import os
from pathlib import Path
import time
from mitmproxy import http

ROOT = Path(os.environ['IOS_PROXY_WORK'])
OUTPUT = Path(os.environ['IOS_PROXY_OUTPUT'])
SECRET_HEADERS = {'authorization', 'cookie', 'set-cookie', 'proxy-authorization'}


class Capture:
    def __init__(self):
        self.count = 0

    def rules(self):
        try:
            return json.loads((ROOT / 'rules.json').read_text())
        except (OSError, ValueError):
            return []

    def request(self, flow: http.HTTPFlow):
        for rule in self.rules():
            if rule['url_contains'] in flow.request.pretty_url:
                for k, v in rule.get('request_headers', {}).items():
                    flow.request.headers[k] = v
                if 'request_body' in rule:
                    if flow.request.raw_content is None:
                        flow.metadata['sentinel_skipped_request_mutation']='streamed body unavailable'
                        continue
                    flow.request.content = rule['request_body'].encode()
                flow.metadata['sentinel_modified_request'] = True

    def response(self, flow: http.HTTPFlow):
        for rule in self.rules():
            if rule['url_contains'] in flow.request.pretty_url and 'response_body' in rule:
                if flow.response.raw_content is None:
                    flow.metadata['sentinel_skipped_response_mutation']='streamed body unavailable'
                    continue
                flow.response.content = rule['response_body'].encode()
                flow.metadata['sentinel_modified_response'] = True
        if self.count >= 1000 or (OUTPUT.exists() and OUTPUT.stat().st_size >= 45*1024*1024):
            return
        self.count += 1
        record = {'time': time.time(), 'method': flow.request.method, 'url': flow.request.pretty_url[:8192],
                  'status': flow.response.status_code,
                  'request_headers': {k[:256]: '[redacted]' if k.lower() in SECRET_HEADERS else v[:2048] for k,v in list(flow.request.headers.items())[:80]},
                  'response_headers': {k[:256]: '[redacted]' if k.lower() in SECRET_HEADERS else v[:2048] for k,v in list(flow.response.headers.items())[:80]},
                  'request_body_base64': base64.b64encode((flow.request.raw_content or b'')[:8192]).decode(),
                  'response_body_base64': base64.b64encode((flow.response.raw_content or b'')[:8192]).decode(),
                  'body_preview_limit':8192,
                  'request_body_available':flow.request.raw_content is not None,
                  'response_body_available':flow.response.raw_content is not None,
                  'request_body_truncated':flow.request.raw_content is None or len(flow.request.raw_content)>8192,
                  'response_body_truncated':flow.response.raw_content is None or len(flow.response.raw_content)>8192,
                  'skipped_request_mutation':flow.metadata.get('sentinel_skipped_request_mutation'),
                  'skipped_response_mutation':flow.metadata.get('sentinel_skipped_response_mutation'),
                  'modified_request':bool(flow.metadata.get('sentinel_modified_request')),
                  'modified_response':bool(flow.metadata.get('sentinel_modified_response'))}
        encoded=(json.dumps(record,ensure_ascii=False)+'\n').encode()
        if (OUTPUT.stat().st_size if OUTPUT.exists() else 0)+len(encoded)>48*1024*1024:
            return
        with OUTPUT.open('ab') as stream:
            stream.write(encoded)


addons = [Capture()]
