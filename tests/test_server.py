"""Real HTTP MCP and local HTTP target tests; no user device or external target."""
import base64
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import plistlib
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import zipfile

from server import Application, TOOLS, handler_for
from jobs import Jobs


def wait_job(app, job_id):
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        state=app.jobs.get(job_id)
        if state['status'] not in ('running','stopping'): return state
        time.sleep(.02)
    raise AssertionError('Job did not finish')


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.app=Application(self.root/'data',self.root/'artifacts')
        self.http=ThreadingHTTPServer(('127.0.0.1',0),handler_for(self.app))
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True)
        self.thread.start()

    def tearDown(self):
        self.app.jobs.shutdown()
        for job in list(self.app.jobs.running): wait_job(self.app,job)
        self.app.device.disconnect()
        self.http.shutdown();self.http.server_close();self.thread.join()
        self.temp.cleanup()

    def request(self,method,path,payload=None,headers=None):
        client=http.client.HTTPConnection('127.0.0.1',self.http.server_port,timeout=5)
        raw=json.dumps(payload).encode() if payload is not None else None
        client.request(method,path,raw,headers or {})
        response=client.getresponse();status=response.status;data=response.read();meta=dict(response.getheaders());client.close()
        return status,data,meta

    def rpc(self,method,params=None):
        _,raw,_=self.request('POST','/mcp',{'jsonrpc':'2.0','id':7,'method':method,'params':params or {}})
        return json.loads(raw)

    def call(self,name,args=None):
        answer=self.rpc('tools/call',{'name':name,'arguments':args or {}})['result']
        return answer,json.loads(answer['content'][0]['text'])

    def test_health_static_and_mcp(self):
        status,raw,_=self.request('GET','/healthz');self.assertEqual(status,200);self.assertTrue(json.loads(raw)['ok'])
        for path in ('index.html','app.js','sdk.js','base.css','app.css'):
            status,body,_=self.request('GET','/ui/'+path);self.assertEqual(status,200);self.assertTrue(body)
        self.assertEqual(self.request('HEAD','/ui/index.html')[1],b'')
        self.assertEqual(self.request('GET','/ui/%2e%2e/server.py')[0],404)
        self.assertEqual(self.rpc('initialize')['result']['protocolVersion'],'2025-03-26')
        self.assertEqual(len(self.rpc('tools/list')['result']['tools']),len(TOOLS))
        self.assertEqual(self.rpc('ping')['result'],{})

    def test_bad_json_notifications_origin_and_methods(self):
        conn=http.client.HTTPConnection('127.0.0.1',self.http.server_port)
        conn.request('POST','/mcp',b'{');res=conn.getresponse();self.assertEqual(res.status,400);self.assertEqual(json.loads(res.read())['error']['code'],-32700);conn.close()
        self.assertEqual(self.request('POST','/mcp',{'jsonrpc':'2.0','method':'notifications/initialized'})[0],202)
        self.assertEqual(self.request('POST','/mcp',{'jsonrpc':'2.0','id':1,'method':'ping'}, {'Origin':'https://untrusted.invalid'})[0],403)
        self.assertEqual(self.rpc('unknown')['error']['code'],-32601)
        self.assertEqual(self.rpc('tools/call',{'name':'x','arguments':[]})['error']['code'],-32602)
        self.assertEqual(self.rpc('ping')['id'],7)

    def test_schema_errors_are_mcp_errors_not_http_500(self):
        for name,args in [('missing',{}),('ios_hook_start',{}),('ios_hook_start',{'bundle_id':'test.app','duration':9999}),('ios_device_status',{'refresh':'true'})]:
            result,_=self.call(name,args);self.assertTrue(result['isError'])

    def test_config_secret_never_returned_in_exception(self):
        with patch.dict(os.environ,{'PLUGIN_SSH_PASSWORD':'sentinel-fixture-secret'}),patch.object(self.app.device,'probe',side_effect=RuntimeError('bad sentinel-fixture-secret')):
            result,text=self.call('ios_device_probe')
            self.assertTrue(result['isError']);self.assertNotIn('sentinel-fixture-secret',json.dumps(result));self.assertIn('[redacted]',text['error'])

    def test_hook_defaults_and_overrides(self):
        with patch('operations.hook',return_value={'events':0}) as execute:
            result,state=self.call('ios_hook_start',{'bundle_id':'test.app','profile':'crypto','duration':5})
            self.assertFalse(result['isError']);self.assertEqual(wait_job(self.app,state['job_id'])['status'],'completed')
            self.assertEqual(execute.call_args.args[2]['profile'],'crypto')
        result,_=self.call('ios_hook_start',{'bundle_id':'test.app','profile':'crypto','replace_from':'x','replace_to':'long'})
        self.assertTrue(result['isError'])

    def test_real_ipa_upload_analyze_and_artifacts(self):
        source=io.BytesIO()
        with zipfile.ZipFile(source,'w') as z:
            z.writestr('Payload/Test.app/Info.plist',plistlib.dumps({'CFBundleIdentifier':'test.app','CFBundleExecutable':'Test','NSAppTransportSecurity':{'NSAllowsArbitraryLoads':True}}))
            z.writestr('Payload/Test.app/main.js','fetch("https://api.example.test/v1/users")')
        raw=source.getvalue()
        _,upload=self.call('ios_package_import_start',{'filename':'test.ipa','size':len(raw)})
        bad,_=self.call('ios_package_import_chunk',{'upload_id':upload['upload_id'],'offset':1,'data_base64':base64.b64encode(raw).decode()});self.assertTrue(bad['isError'])
        result,received=self.call('ios_package_import_chunk',{'upload_id':upload['upload_id'],'offset':0,'data_base64':base64.b64encode(raw).decode()});self.assertFalse(result['isError']);self.assertEqual(received['offset'],len(raw))
        _,job=self.call('ios_package_import_finish',{'upload_id':upload['upload_id']})
        state=wait_job(self.app,job['job_id']);self.assertEqual(state['status'],'completed',state)
        self.assertTrue(any(p.endswith('static-analysis.json') for p in state['artifacts']))
        result,status=self.call('ios_job_status',{'job_id':job['job_id']});self.assertEqual(result['_meta']['artifacts'],state['artifacts'])
        self.assertFalse((self.app.jobs.data/job['job_id']/'import.ipa').exists())
        _,deleted=self.call('ios_job_delete',{'job_id':job['job_id']});self.assertEqual(deleted['deleted'],job['job_id'])

    def test_cancel_and_restart_status(self):
        def slow(job):
            while True: job.check();time.sleep(.02)
        state=self.app.jobs.start('slow',slow)
        result,_=self.call('ios_device_disconnect');self.assertTrue(result['isError'])
        self.call('ios_job_stop',{'job_id':state['job_id']})
        self.assertEqual(wait_job(self.app,state['job_id'])['status'],'cancelled')
        path=self.app.jobs.data/state['job_id']/'state.json'
        saved=json.loads(path.read_text());saved['status']='running';path.write_text(json.dumps(saved))
        fresh=Jobs(self.app.data,self.app.jobs.artifacts)
        self.assertEqual(fresh.get(state['job_id'])['status'],'interrupted')

    def test_paginated_long_names_are_not_discarded(self):
        apps=[{'bundle_id':'test.app'+str(i),'name':'长名称'*200} for i in range(100)]
        with patch.object(self.app.device,'apps',return_value=apps):
            _,one=self.call('ios_apps_list',{'offset':0,'limit':100})
            self.assertGreater(len(one['apps']),0);self.assertLess(len(one['apps']),100)
            self.assertEqual(one['next_offset'],len(one['apps']))
            _,two=self.call('ios_apps_list',{'offset':one['next_offset'],'limit':100})
            self.assertEqual(two['apps'][0]['bundle_id'],apps[one['next_offset']]['bundle_id'])

    def test_api_anonymous_and_identity_are_isolated(self):
        observations=[]
        class Target(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                observations.append(dict(self.headers))
                self.send_response(200 if self.headers.get('Authorization')=='Bearer fixture' else 401)
                self.send_header('Set-Cookie','must-not-leak=1')
                self.end_headers();self.wfile.write(b'fixture response')
        target=ThreadingHTTPServer(('127.0.0.1',0),Target)
        thread=threading.Thread(target=target.serve_forever,daemon=True);thread.start()
        try:
            _,job=self.call('ios_api_check',{'url':f'http://127.0.0.1:{target.server_port}/test','headers':{'Authorization':'Bearer fixture'}})
            state=wait_job(self.app,job['job_id']);self.assertEqual(state['status'],'completed',state)
            self.assertEqual([s['status'] for s in state['result']['samples']],[401,200])
            self.assertNotIn('Authorization',observations[0]);self.assertEqual(observations[1]['Authorization'],'Bearer fixture')
            self.assertTrue(all('Cookie' not in h for h in observations))
            self.assertFalse(state['result']['confirmed_vulnerability'])
        finally:
            target.shutdown();target.server_close();thread.join()


if __name__=='__main__':unittest.main()
