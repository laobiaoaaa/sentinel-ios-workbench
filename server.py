#!/usr/bin/env python3
"""Sentinel iOS Workbench: streamable HTTP MCP + sandbox UI static files."""
import base64
import binascii
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import re
import signal
import threading
import time
from urllib.parse import unquote, urlsplit
import uuid
from jsonschema import Draft202012Validator
from device import Device
from jobs import Jobs, atomic_json, scrub
import operations

VERSION = '0.1.0'
HERE = Path(__file__).parent
DATA = Path(os.environ.get('PLUGIN_DATA_DIR','/data'))
ARTIFACTS = Path(os.environ.get('PLUGIN_ARTIFACTS_DIR','/artifacts'))
STRING = {'type':'string'}
BUNDLE = {'type':'string','pattern':r'^[A-Za-z0-9][A-Za-z0-9._-]{1,254}$'}
JOB = {'type':'string','pattern':r'^run-[0-9]{8}-[0-9]{6}-[a-f0-9]{12}$'}
DURATION = {'type':'integer','minimum':5,'maximum':600,'default':30}
HEADERS = {'type':'object','maxProperties':60,'additionalProperties':{'type':'string','maxLength':8192}}


def tool(name, description, properties=None, required=(), readonly=False):
    return {'name':name,'description':description,'inputSchema':{
        'type':'object','properties':properties or {},'required':list(required),'additionalProperties':False},
        'annotations':{'readOnlyHint':readonly,'destructiveHint':False,'openWorldHint':True}}


TOOLS = [
    tool('ios_device_probe','读取配置设备的 SSH 主机指纹，不发送密码；用于核对或诊断连接。',readonly=True),
    tool('ios_device_connect','通过插件自身 SSH 连接设备，自动首次记录主机密钥、读取设备信息和工具能力；主机密钥变化拒绝连接。'),
    tool('ios_device_status','读取设备在线状态；refresh=true 执行真实在线检测，不把历史缓存当在线。',{'refresh':{'type':'boolean','default':False}},readonly=True),
    tool('ios_device_disconnect','断开本插件 SSH；运行任务须先停止，不操作平台旧设备页面。'),
    tool('ios_apps_list','通过 SSH/SFTP 分页列出设备应用及 Bundle ID。先连接设备。',{'offset':{'type':'integer','minimum':0},'limit':{'type':'integer','minimum':1,'maximum':100}},readonly=True),
    tool('ios_test_start','启动 iOS 客户端静态分析/网络观察任务。client=静态+网络；backend=网络观察并整理接口；combined=两者。返回 job_id 后用 ios_job_status 取进度。接口主动验证另用 ios_api_check；不能把候选当漏洞。',
         {'bundle_id':BUNDLE,'mode':{'type':'string','enum':['client','backend','combined'],'default':'combined'},'duration':DURATION},['bundle_id']),
    tool('ios_hook_start','实际通过 SSH 隧道运行 Frida Hook。network观察请求/支持的TLS函数，crypto观察CommonCrypto，storage观察文件/Keychain调用。自动选择可连接的内置Frida运行时。crypto可选进程内CCCrypt加密输入的等UTF-8字节长度替换，不证明网络请求已修改；无密钥采集。',
         {'bundle_id':BUNDLE,'duration':DURATION,'profile':{'type':'string','enum':['network','crypto','storage'],'default':'network'},
          'replace_from':{'type':'string','maxLength':512},'replace_to':{'type':'string','maxLength':512}},['bundle_id']),
    tool('ios_dump_start','拷贝应用并通过 Frida 导出已加载模块的加密区域，校验剩余加密组件；大IPA按48MiB分片。需设备端可用Frida，不等于恢复源码或可重签安装。',{'bundle_id':BUNDLE},['bundle_id']),
    tool('ios_proxy_start','启动真实 mitmproxy 抓改包服务和设备 localhost SSH 反向隧道。返回任务connection信息；设备/App需使用代理并按需信任CA。不会假称已自动配置设备或绕过固定证书。',
         {'duration':DURATION,'reverse':{'const':True,'default':True}}),
    tool('ios_proxy_rules_set','对正在运行的代理设置明确URL匹配的请求头/请求体/响应体替换规则，空数组清除。',
         {'job_id':JOB,'rules':{'type':'array','maxItems':20,'items':{'type':'object','additionalProperties':False,
            'properties':{'url_contains':{'type':'string','minLength':8,'maxLength':2048},'request_headers':HEADERS,
                          'request_body':{'type':'string','maxLength':65536},'response_body':{'type':'string','maxLength':65536}},'required':['url_contains']}}},['job_id','rules']),
    tool('ios_api_check','对指定HTTP(S)接口发送基线与可选两身份请求。base_headers用于所有请求的通用头，身份头分别用headers/compare_headers覆盖；方法与body共用。基线头、URL、body中身份字段需由调用者清除才是匿名；响应相似不自动判为越权，不跟随重定向，不保存请求头。',
         {'url':{'type':'string','minLength':8,'maxLength':8192},'method':{'type':'string','enum':['GET','HEAD','POST','PUT','PATCH','DELETE'],'default':'GET'},
          'base_headers':HEADERS,'headers':HEADERS,'compare_headers':HEADERS,'body':{'type':'string','maxLength':65536}},['url']),
    tool('ios_package_import_start','开始通过工具分片导入IPA，不依赖宿主路径或私有上传接口。',
         {'filename':{'type':'string','pattern':r'^[^/\\]{1,150}\.(ipa|zip)$'},'size':{'type':'integer','minimum':1,'maximum':536870912}},['filename','size']),
    tool('ios_package_import_chunk','追加IPA分片。offset必须等于已接收字节数，data_base64解码后最多256KiB。',
         {'upload_id':{'type':'string','pattern':'^[a-f0-9]{32}$'},'offset':{'type':'integer','minimum':0},'data_base64':{'type':'string','maxLength':349528}},['upload_id','offset','data_base64']),
    tool('ios_package_import_finish','校验IPA接收长度并启动静态分析任务。',{'upload_id':{'type':'string','pattern':'^[a-f0-9]{32}$'}},['upload_id']),
    tool('ios_package_import_cancel','删除未完成的上传文件。',{'upload_id':{'type':'string','pattern':'^[a-f0-9]{32}$'}},['upload_id']),
    tool('ios_job_status','查询一个任务的阶段、真实结果/失败原因和产物路径。',{'job_id':JOB},['job_id'],True),
    tool('ios_jobs_list','分页列出本插件保留的任务摘要。详细结果使用 ios_job_status。',{'offset':{'type':'integer','minimum':0},'limit':{'type':'integer','minimum':1,'maximum':20}},readonly=True),
    tool('ios_job_stop','停止任务并清理本插件的Hook/代理/隧道；不终止设备应用。',{'job_id':JOB},['job_id']),
    tool('ios_job_delete','删除已结束任务及其产物，释放插件空间。',{'job_id':JOB},['job_id']),
]
CATALOG = {t['name']:t for t in TOOLS}


class Application:
    def __init__(self,data=DATA,artifacts=ARTIFACTS):
        data.mkdir(parents=True,exist_ok=True)
        self.data=data
        self.device=Device(data)
        self.jobs=Jobs(data,artifacts)
        self.uploads={}
        self.upload_lock=threading.RLock()
        self.control_lock=threading.RLock()
        self.upload_dir=data/'uploads'
        self.upload_dir.mkdir(exist_ok=True)
        # Upload ids are process-owned. A partial upload is never silently resumed.
        for path in self.upload_dir.glob('*.part'):
            path.unlink()

    def idle(self):
        if self.jobs.busy():
            raise ValueError('有任务运行中，请先停止任务再更改连接')

    def call(self,name,args):
        if name not in CATALOG: raise ValueError('未知工具')
        errors=list(Draft202012Validator(CATALOG[name]['inputSchema']).iter_errors(args))
        if errors:
            raise ValueError('参数不符合 inputSchema：'+str(list(errors[0].absolute_path)))
        with self.control_lock:
            if name=='ios_device_probe': return self.device.probe()
            if name=='ios_device_connect': self.idle(); return self.device.connect()
            if name=='ios_device_status': return self.device.status(args.get('refresh',False))
            if name=='ios_device_disconnect': self.idle(); return self.device.disconnect()
            if name in ('ios_apps_list','ios_jobs_list'):
                key='apps' if name=='ios_apps_list' else 'jobs'
                items=self.device.apps() if key=='apps' else self.jobs.list()
                offset=args.get('offset',0)
                end=offset+args.get('limit',100 if key=='apps' else 20)
                selected=[{k:v for k,v in item.items() if (k in ('bundle_id','name') if key=='apps' else k!='result')} for item in items[offset:end]]
                while len(selected)>1 and len(json.dumps(selected,ensure_ascii=False).encode())>18000:
                    selected.pop()
                end=offset+len(selected)
                return {key:selected,'total':len(items),'next_offset':end if end<len(items) else None}
            if name=='ios_job_status': return self.jobs.get(args['job_id'])
            if name=='ios_job_stop': return self.jobs.cancel(args['job_id'])
            if name=='ios_job_delete': return self.jobs.delete(args['job_id'])
            if name=='ios_test_start':
                return self.jobs.start('assessment',lambda j:operations.client_test(j,self.device,args))
            if name=='ios_hook_start':
                opts={'duration':30,'profile':'network',**args}
                if ('replace_from' in opts) != ('replace_to' in opts):
                    raise ValueError('替换必须同时提供 replace_from 与 replace_to')
                if opts.get('replace_from') and (opts['profile']!='crypto' or len(opts['replace_from'].encode())!=len(opts['replace_to'].encode())):
                    raise ValueError('仅 crypto 支持等UTF-8字节长度的明确替换')
                return self.jobs.start('hook',lambda j:operations.hook(j,self.device,opts))
            if name=='ios_dump_start': return self.jobs.start('dump',lambda j:operations.dump(j,self.device,args))
            if name=='ios_api_check': return self.jobs.start('api',lambda j:operations.api_check(j,args),'api')
            if name=='ios_proxy_start': return self.jobs.start('proxy',lambda j:operations.proxy(j,self.device,args),'proxy')
            if name=='ios_proxy_rules_set':
                state=self.jobs.get(args['job_id'])
                if state['kind']!='proxy' or state['status']!='running' or state['stage']!='capturing':
                    raise ValueError('代理尚未就绪或已结束')
                for rule in args['rules']:
                    for k,v in rule.get('request_headers',{}).items():
                        if '\n' in k+v or '\r' in k+v: raise ValueError('请求头不允许换行')
                atomic_json(self.jobs.data/args['job_id']/'rules.json',args['rules'])
                return {'applied_rules':len(args['rules'])}
            if name.startswith('ios_package_import_'): return self.upload(name,args)
        raise ValueError('未实现工具')

    def upload(self,name,args):
        with self.upload_lock:
            now=time.time()
            for key,record in list(self.uploads.items()):
                if now-record['updated']>3600:
                    record['path'].unlink(missing_ok=True); del self.uploads[key]
            if name=='ios_package_import_start':
                if len(self.uploads)>=2: raise ValueError('最多同时保留两个未完成上传')
                key=uuid.uuid4().hex
                path=self.upload_dir/(key+'.part')
                path.touch(mode=0o600)
                self.uploads[key]={'path':path,'size':args['size'],'offset':0,'updated':now}
                return {'upload_id':key,'chunk_bytes':262144}
            key=args['upload_id']
            record=self.uploads.get(key)
            if not record: raise ValueError('上传不存在、已失效或插件已重启')
            if name=='ios_package_import_cancel':
                record['path'].unlink(missing_ok=True); del self.uploads[key]
                return {'cancelled':key}
            if name=='ios_package_import_chunk':
                try: chunk=base64.b64decode(args['data_base64'],validate=True)
                except (ValueError,binascii.Error): raise ValueError('分片不是合法base64') from None
                if not chunk or len(chunk)>262144 or args['offset']!=record['offset'] or record['offset']+len(chunk)>record['size']:
                    raise ValueError('分片大小、顺序或总长度不匹配')
                with record['path'].open('ab') as out: out.write(chunk)
                record.update(offset=record['offset']+len(chunk),updated=now)
                return {'offset':record['offset']}
            if record['offset']!=record['size']: raise ValueError('文件尚未完整接收')
            def run(job):
                target=job.work/'import.ipa'
                record['path'].replace(target)
                return operations.analyze(job,target)
            job=self.jobs.start('package_analysis',run,'static')
            del self.uploads[key]
            return job

    def rpc(self,message):
        if not isinstance(message,dict) or message.get('jsonrpc')!='2.0' or not isinstance(message.get('method'),str):
            return error(None,-32600,'invalid request')
        ident=message.get('id')
        if 'id' not in message:
            return None
        if isinstance(ident,(dict,list,bool)):
            return error(None,-32600,'invalid id')
        method=message['method']
        if method=='initialize':
            result={'protocolVersion':'2025-03-26','capabilities':{'tools':{}},'serverInfo':{'name':'sentinel-ios','version':VERSION}}
        elif method=='ping': result={}
        elif method=='tools/list': result={'tools':TOOLS}
        elif method in ('resources/list','prompts/list'):
            result={method.split('/')[0]:[]}
        elif method=='tools/call':
            params=message.get('params',{})
            if not isinstance(params,dict) or not isinstance(params.get('arguments',{}),dict):
                return error(ident,-32602,'invalid params')
            try:
                value=scrub(self.call(params.get('name'),params.get('arguments',{})))
                body=json.dumps(value,ensure_ascii=False)
                artifacts=value.get('artifacts',[]) if isinstance(value,dict) else []
                if len(body.encode())>24000:
                    value={k:v for k,v in value.items() if k not in ('result','jobs','apps')}
                    value['summary']='输出较大；完整结果见任务产物。'
                    body=json.dumps(value,ensure_ascii=False)
                result={'content':[{'type':'text','text':body}],'isError':False,'_meta':{'artifacts':artifacts}}
            except Exception as exc:
                result={'isError':True,'content':[{'type':'text','text':json.dumps({'error':scrub(str(exc))[:1500]},ensure_ascii=False)}]}
        else: return error(ident,-32601,'method not found')
        return {'jsonrpc':'2.0','id':ident,'result':result}


def error(ident,code,message):
    return {'jsonrpc':'2.0','id':ident,'error':{'code':code,'message':message}}


def handler_for(app):
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def setup(self):
            super().setup(); self.connection.settimeout(30)
        def log_message(self,*unused): pass
        def send(self,status,payload=None,head=False,mime='application/json; charset=utf-8'):
            raw=payload if isinstance(payload,bytes) else json.dumps(payload,ensure_ascii=False).encode() if payload is not None else b''
            self.send_response(status)
            self.send_header('Content-Type',mime)
            self.send_header('Content-Length',str(len(raw)))
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Cache-Control','no-store')
            self.end_headers()
            if not head: self.wfile.write(raw)
        def do_HEAD(self): self.do_GET(True)
        def do_GET(self,head=False):
            path=unquote(urlsplit(self.path).path)
            if path=='/healthz': return self.send(200,{'ok':True,'version':VERSION},head)
            if path=='/mcp': return self.send(405,{'error':'POST required'},head)
            if path.startswith('/ui/'):
                target=(HERE/path.lstrip('/')).resolve()
                if target.parent==HERE/'ui' and target.is_file() and not target.is_symlink():
                    return self.send(200,target.read_bytes(),head,mimetypes.guess_type(target)[0] or 'application/octet-stream')
            return self.send(404,{'error':'not found'},head)
        def do_POST(self):
            if urlsplit(self.path).path!='/mcp': return self.send(404,{'error':'not found'})
            if self.headers.get('Origin'): return self.send(403,{'error':'UI must use Sentinel SDK'})
            try: length=int(self.headers.get('Content-Length','0'))
            except ValueError: length=-1
            if length<=0 or length>1024*1024 or self.headers.get('Transfer-Encoding'):
                self.close_connection=True
                return self.send(413,error(None,-32600,'invalid body size'))
            try:
                message=json.loads(self.rfile.read(length))
            except (ValueError,UnicodeDecodeError): return self.send(400,error(None,-32700,'parse error'))
            if isinstance(message,list):
                if not message or len(message)>20: return self.send(400,error(None,-32600,'invalid batch'))
                result=[r for m in message if (r:=app.rpc(m)) is not None]
                return self.send(200,result) if result else self.send(202)
            result=app.rpc(message)
            return self.send(200,result) if result is not None else self.send(202)
        def do_DELETE(self): self.send(405,{'error':'stateless transport'})
    return Handler


def main():
    os.umask(0o077)
    app=Application()
    server=ThreadingHTTPServer(('0.0.0.0',int(os.environ.get('PORT','7801'))),handler_for(app))
    server.daemon_threads=True
    def stop(*unused):
        app.jobs.shutdown()
        threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,stop)
    signal.signal(signal.SIGINT,stop)
    print('sentinel-ios ready',flush=True)
    try: server.serve_forever(poll_interval=.2)
    finally:
        app.jobs.shutdown()
        deadline=time.monotonic()+7
        while app.jobs.busy() and time.monotonic()<deadline: time.sleep(.1)
        app.device.disconnect()
        server.server_close()


if __name__=='__main__': main()
