"""Real task implementations. No platform-private API or Docker socket."""
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import zipfile
import httpx
from jobs import atomic_json, scrub
from static_analysis import analyze_package, inspect_macho

HERE = Path(__file__).parent


def app_for(device, bundle_id):
    app = next((a for a in device.apps() if a['bundle_id'] == bundle_id), None)
    if not app:
        raise ValueError('未找到此 Bundle ID；先刷新设备应用列表')
    return app


def terminate(proc):
    forced = False
    if proc.poll() is None:
        proc.terminate()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            forced = True
            proc.kill()
            proc.wait(timeout=5)
    return forced


def worker(job, python, request, events=None):
    job.check()
    proc = subprocess.Popen([python, '-u', str(HERE/'frida_worker.py')], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                            env={k:v for k,v in os.environ.items() if not k.startswith('PLUGIN_SSH_')})
    lines = queue.Queue(maxsize=64)
    def reader():
        try:
            for line in proc.stdout:
                if len(line) <= 256*1024:
                    while proc.poll() is None:
                        try: lines.put(line, timeout=.2); break
                        except queue.Full: pass
                    else:
                        try: lines.put(line, timeout=1)
                        except queue.Full: pass
        finally:
            lines.put(None)
    threading.Thread(target=reader, daemon=True).start()
    error, result, cleanup = None, None, None
    deadline = time.monotonic() + request.get('duration', 120) + 30
    try:
        proc.stdin.write(json.dumps(request)+'\n')
        proc.stdin.close()
        while time.monotonic() < deadline:
            job.check()
            try: line = lines.get(timeout=.2)
            except queue.Empty: continue
            if line is None:
                break
            message = json.loads(line)
            if 'event' in message and events:
                events(scrub(message['event']))
            if message.get('ready'):
                job.update(stage='observing' if request['action']=='hook' else 'dumping', runtime=message['runtime'], pid=message['pid'])
            if 'error' in message:
                error = message['error']
            if 'cleanup' in message:
                cleanup = message['cleanup']
            if message.get('spawned'):
                job.update(spawned_pid=message['pid'])
            if 'result' in message:
                result = message['result']
        if result is None:
            raise RuntimeError(error or 'Frida 任务超时或执行进程异常退出')
        return result
    finally:
        forced=terminate(proc)
        until=time.monotonic()+1
        while time.monotonic()<until:
            try: line=lines.get(timeout=.05)
            except queue.Empty:
                if proc.poll() is not None: break
                continue
            if line is None: break
            try:
                message=json.loads(line)
                if 'cleanup' in message: cleanup=message['cleanup']
            except ValueError: pass
        if forced or not cleanup:
            cleanup={'confirmed':False,'forced_kill':forced,'note':'未收到设备端清理确认；需检查目标应用状态'}
        job.update(runtime_cleanup=cleanup)
        if isinstance(result,dict): result['cleanup']=cleanup


def runtimes():
    paths = ['/opt/frida17/bin/python', '/opt/frida16/bin/python']
    installed = [p for p in paths if Path(p).is_file()]
    return installed or [sys.executable]


@contextlib.contextmanager
def frida_connection(job, device):
    job.update(stage='frida_capability_probe')
    failures = []
    with device.forward('127.0.0.1', int(os.environ.get('PLUGIN_FRIDA_PORT','27042'))) as port:
        address = '127.0.0.1:' + str(port)
        for python in runtimes():
            try:
                result = worker(job, python, {'action':'probe','address':address,'duration':10})
            except Exception as exc:
                job.check()
                failures.append(str(exc)[:250])
                continue
            yield python, address, result
            return
    raise RuntimeError('设备端 Frida 不可用或版本不兼容；已尝试内置运行时。' + ' / '.join(failures))


def hook(job, device, args):
    observations = []
    output = job.out / 'hook-events.jsonl'
    try:
        with output.open('w', encoding='utf-8') as stream:
            def record(event):
                if len(observations) >= 2000:
                    return
                observations.append(event)
                stream.write(json.dumps(event, ensure_ascii=False)+'\n')
                stream.flush()
            with frida_connection(job, device) as (python,address,_):
                request = dict(args, action='hook', address=address)
                result = worker(job,python,request,record)
    finally:
        job.register(output.name)
    urls = sorted({e['url'] for e in observations if e.get('url')})
    job.artifact('observed-endpoints.json', {'urls':urls, 'source':'runtime_observation', 'verified_vulnerabilities':[]})
    result.update(observed_urls=urls[:100], observed_events=len(observations))
    return result


def analyze(job, path):
    job.check()
    job.update(stage='static_analysis')
    report = analyze_package(path, job.out)
    for name in report.get('files',[]):
        job.register(name)
    return report


def client_test(job, device, args):
    job.update(stage='device_probe')
    status = device.connect()
    job.artifact('device.json',status)
    app = app_for(device,args['bundle_id'])
    result = {'app':app,'steps':[], 'unverified':[]}
    if args.get('mode','client') in ('client','combined'):
        job.update(stage='copy_application')
        local = job.work/'Payload'/Path(app['path']).name
        copied = device.download_tree(app['path'], local, cancel=job.check)
        static = analyze(job,local)
        result['steps'].append({'stage':'static','result':static,'copied_bytes':copied['bytes'],
                                'skipped_symlinks':copied.get('skipped_symlinks',[])})
    try:
        observed = hook(job,device,dict(bundle_id=args['bundle_id'],profile='network',duration=args.get('duration',30)))
        result['steps'].append({'stage':'network_observation','result':observed})
    except Exception as exc:
        job.check()
        result['unverified'].append({'stage':'network_observation','reason':str(exc)[:800]})
    result['unverified'].append({'stage':'business_authorization','reason':'使用 ios_api_check 验证具体接口；需要角色对比的结论必须有对应身份和业务证据'})
    result['coverage']='静态配置和接口候选 + 动态网络观察；不是所有漏洞类型的自动证明'
    job.artifact('assessment.json',result)
    return result


def binary_slice(stream, cpu, subtype):
    """Validate and describe the exact disk slice before patching runtime bytes.

    Returns file-relative slice coordinates, UUID, segments and encryption commands.
    Unsupported/malformed formats fail explicitly; no architecture fallback.
    """
    stream.seek(0, 2)
    file_size = stream.tell()
    def read(offset, length, limit=file_size):
        if offset < 0 or length < 0 or offset + length > limit:
            raise ValueError('Mach-O 范围越界')
        stream.seek(offset)
        value = stream.read(length)
        if len(value) != length:
            raise ValueError('Mach-O 文件截断')
        return value
    thin = {b'\xce\xfa\xed\xfe': ('<', 32), b'\xcf\xfa\xed\xfe': ('<', 64)}
    fat = {b'\xca\xfe\xba\xbe': ('>', 32), b'\xca\xfe\xba\xbf': ('>', 64),
           b'\xbe\xba\xfe\xca': ('<', 32), b'\xbf\xba\xfe\xca': ('<', 64)}
    magic = read(0, 4)
    offset, size = 0, file_size
    if magic in fat:
        endian, width = fat[magic]
        count = struct.unpack(endian + 'I', read(4, 4))[0]
        entry_size = 32 if width == 64 else 20
        if not 0 < count <= 128 or 8 + count * entry_size > file_size:
            raise ValueError('异常的 fat 架构表')
        matches, ranges = [], []
        for index in range(count):
            values = struct.unpack(endian + ('IIQQII' if width == 64 else 'IIIII'),
                                   read(8 + index * entry_size, entry_size))
            found_cpu, found_sub, start, length, align = values[:5]
            if not length or start < 8 + count * entry_size or start + length > file_size or align > 63 or start % (1 << align):
                raise ValueError('fat slice 范围或对齐无效')
            if any(start < right and start + length > left for left, right in ranges):
                raise ValueError('fat slice 重叠')
            ranges.append((start, start + length))
            if found_cpu == cpu and (found_sub & 0xffffff) == (subtype & 0xffffff):
                matches.append((start, length))
        if len(matches) != 1:
            raise ValueError('未找到唯一匹配的运行架构 slice')
        offset, size = matches[0]
        magic = read(offset, 4)
    if magic not in thin:
        raise ValueError('仅支持 iOS little-endian 32/64 位 Mach-O slice')
    endian, bits = thin[magic]
    header_size = 32 if bits == 64 else 28
    header = read(offset, header_size, offset + size)
    _, found_cpu, found_sub, _, count, command_bytes, _ = struct.unpack_from(endian + 'IIIIIII', header)
    if found_cpu != cpu or (found_sub & 0xffffff) != (subtype & 0xffffff):
        raise ValueError('运行进程与磁盘 slice 架构不匹配')
    if count > 4096 or command_bytes > 16 * 1024 * 1024 or count * 8 > command_bytes or header_size + command_bytes > size:
        raise ValueError('Mach-O load commands 超出限制')
    cursor, end = offset + header_size, offset + header_size + command_bytes
    result = {'offset': offset, 'size': size, 'bits': bits, 'cpu': found_cpu,
              'subtype': found_sub, 'uuid': None, 'segments': [], 'encryption': []}
    for _ in range(count):
        command, length = struct.unpack(endian + 'II', read(cursor, 8, end))
        if length < 8 or length % 4 or cursor + length > end:
            raise ValueError('Mach-O load command 大小无效')
        data = read(cursor, length, end)
        if command == 0x1b:
            if length != 24 or result['uuid'] is not None:
                raise ValueError('Mach-O UUID 命令无效')
            result['uuid'] = data[8:24].hex()
        elif command in (1, 0x19):
            is64 = command == 0x19
            minimum = 72 if is64 else 56
            if length < minimum or len(result['segments']) >= 128:
                raise ValueError('Mach-O segment 命令无效')
            values = struct.unpack_from(endian + ('QQQQiiII' if is64 else 'IIIIiiII'), data, 24)
            vmaddr, vmsize, fileoff, filesize, _maxprot, _initprot, nsects, _flags = values
            if minimum + nsects * (80 if is64 else 68) > length or fileoff + filesize > size or filesize > vmsize:
                raise ValueError('Mach-O segment/section 范围无效')
            result['segments'].append({'name': data[8:24].split(b'\0', 1)[0].decode('utf-8', 'strict'),
                                       'vmaddr': vmaddr, 'vmsize': vmsize, 'fileoff': fileoff, 'filesize': filesize})
        elif command in (0x21, 0x2c):
            if length < (24 if command == 0x2c else 20):
                raise ValueError('Mach-O 加密命令截断')
            cryptoff, cryptsize, cryptid = struct.unpack_from(endian + 'III', data, 8)
            if cryptoff + cryptsize > size or (cryptsize and cryptoff < header_size + command_bytes):
                raise ValueError('Mach-O 加密区超出所选 slice')
            result['encryption'].append({'cryptoff': cryptoff, 'cryptsize': cryptsize, 'original_cryptid': cryptid,
                                         'cryptid_offset': cursor - offset + 16})
        cursor += length
    if cursor != end or result['uuid'] is None:
        raise ValueError('Mach-O 命令区不完整或缺少 UUID，不能验证运行时转储')
    headers = [s for s in result['segments'] if s['fileoff'] == 0 and s['filesize'] >= header_size + command_bytes]
    if len(headers) != 1:
        raise ValueError('Mach-O header 缺少唯一 fileoff→vmaddr 映射')
    result['header_vmaddr'] = headers[0]['vmaddr']
    return result


def dump(job, device, args):
    def canonical(remote):
        return remote[8:] if remote.startswith('/private/var/') else remote
    def region_digest(stream, offset, length):
        stream.seek(offset)
        digest = hashlib.sha256()
        remaining = length
        while remaining:
            job.check()
            block = stream.read(min(1024 * 1024, remaining))
            if not block:
                raise ValueError('转储区域截断')
            digest.update(block)
            remaining -= len(block)
        return digest.hexdigest()
    def segments(value):
        return [(s['name'], *(int(s[k]) for k in ('vmaddr', 'vmsize', 'fileoff', 'filesize'))) for s in value]
    app = app_for(device, args['bundle_id'])
    local = job.work / 'Payload' / Path(app['path']).name
    job.update(stage='copy_application')
    copied = device.download_tree(app['path'], local, cancel=job.check)
    with frida_connection(job, device) as (python, address, _):
        dumped = worker(job, python, dict(action='dump', address=address, bundle_id=args['bundle_id'],
                                         app_path=app['path'], output=str(job.work)))
    records = dumped['regions']
    if not isinstance(records, list) or len(records) > 512:
        raise ValueError('转储区域清单无效')
    patched, seen, total_region_bytes = [], set(), 0
    for region in records:
        job.check()
        for key in ('cpu', 'subtype', 'cryptoff', 'cryptsize', 'cryptid_offset', 'original_cryptid', 'bits'):
            if not isinstance(region[key], int) or isinstance(region[key], bool) or region[key] < 0:
                raise ValueError('运行时转储字段不是有效非负整数')
        rel = Path(canonical(region['path'])).relative_to(canonical(app['path']))
        if not rel.parts or '..' in rel.parts:
            raise ValueError('导出路径越界')
        target = local / rel
        if not target.is_file() or target.is_symlink() or any(p.is_symlink() for p in target.parents if p != local.parent):
            raise ValueError('待修补模块不在应用副本中')
        if not re.fullmatch(r'region-[0-9]+\.bin', region['file']):
            raise ValueError('导出区域文件名无效')
        source_path = job.work / region['file']
        if source_path.is_symlink() or not source_path.is_file() or source_path.stat().st_size != region['cryptsize']:
            raise ValueError('转储区域文件长度或类型不匹配')
        if not 0 < region['cryptsize'] <= 128 * 1024 * 1024 or not region['original_cryptid']:
            raise ValueError('没有有效的原始加密区域')
        total_region_bytes += region['cryptsize']
        if total_region_bytes > 512 * 1024 * 1024:
            raise ValueError('累计转储区域超过限制')
        key = (str(rel), region['cpu'], region['subtype'], region['cryptid_offset'])
        if key in seen:
            raise ValueError('重复的转储区域')
        seen.add(key)
        with target.open('r+b') as stream:
            original_size = target.stat().st_size
            metadata = binary_slice(stream, region['cpu'], region['subtype'])
            if metadata['uuid'] != region['uuid'] or metadata['bits'] != region['bits']:
                raise ValueError('运行时 UUID/位宽与磁盘 slice 不匹配')
            if segments(metadata['segments']) != segments(region['segments']):
                raise ValueError('运行时 segment 映射与磁盘 slice 不匹配')
            expected = {k: region[k] for k in ('cryptoff', 'cryptsize', 'original_cryptid', 'cryptid_offset')}
            if expected not in metadata['encryption']:
                raise ValueError('运行时加密命令与磁盘 slice 不匹配')
            # Every encrypted byte must belong to one file-backed segment, including cross-segment ranges.
            cursor, end = region['cryptoff'], region['cryptoff'] + region['cryptsize']
            while cursor < end:
                matches = [s for s in metadata['segments'] if s['fileoff'] <= cursor < s['fileoff'] + s['filesize']]
                if len(matches) != 1:
                    raise ValueError('加密区缺少唯一 segment 映射')
                cursor = min(end, matches[0]['fileoff'] + matches[0]['filesize'])
            with source_path.open('rb') as source:
                digest = region_digest(source, 0, region['cryptsize'])
                if digest != region['sha256']:
                    raise ValueError('运行时转储区域 SHA-256 不匹配')
                source.seek(0)
                stream.seek(metadata['offset'] + region['cryptoff'])
                remaining = region['cryptsize']
                while remaining:
                    job.check()
                    block = source.read(min(1024 * 1024, remaining))
                    if not block:
                        raise ValueError('写入期间转储文件截断')
                    stream.write(block)
                    remaining -= len(block)
            stream.seek(metadata['offset'] + region['cryptid_offset'])
            stream.write(b'\0' * 4)
            stream.flush()
            if region_digest(stream, metadata['offset'] + region['cryptoff'], region['cryptsize']) != digest:
                raise ValueError('修补后区域 SHA-256 回读失败')
            verified = binary_slice(stream, region['cpu'], region['subtype'])
            if not any(e['cryptid_offset'] == region['cryptid_offset'] and e['original_cryptid'] == 0 for e in verified['encryption']):
                raise ValueError('修补后的 cryptid 回读失败')
            if stream.seek(0, 2) != original_size or metadata['offset'] + metadata['size'] > original_size:
                raise ValueError('修补后模块大小异常')
        patched.append({'file': rel.as_posix(), 'uuid': metadata['uuid'], 'cpu': region['cpu'], 'subtype': region['subtype'],
                        'slice_offset': metadata['offset'], 'cryptoff': region['cryptoff'], 'cryptsize': region['cryptsize'],
                        'sha256': digest, 'runtime_bytes_and_disk_readback_verified': True})
    remaining, unverified, macho_count = [], [], 0
    for path in local.rglob('*'):
        job.check()
        if path.is_file() and not path.is_symlink():
            metadata = inspect_macho(path)
            if metadata.get('is_macho'):
                macho_count += 1
                if not metadata.get('valid') or metadata.get('encrypted') is None:
                    unverified.append(str(path.relative_to(local)))
                if metadata.get('encrypted') is True:
                    remaining.append(str(path.relative_to(local)))
    archive = job.work / 'application.ipa'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=1) as z:
        for path in local.rglob('*'):
            job.check()
            if path.is_file() and not path.is_symlink():
                z.write(path, str(path.relative_to(job.work)))
    parts = []
    with archive.open('rb') as source:
        index = 1
        while block := source.read(48 * 1024 * 1024):
            job.check()
            name = 'application.ipa' if archive.stat().st_size <= 48 * 1024 * 1024 else f'application.ipa.part{index:03d}'
            job.artifact(name, block)
            parts.append({'path': name, 'bytes': len(block), 'sha256': hashlib.sha256(block).hexdigest()})
            index += 1
    with archive.open('rb') as source:
        archive_sha256 = hashlib.file_digest(source, 'sha256').hexdigest()
    result = {'bundle_id': args['bundle_id'], 'exported_regions': len(patched), 'verified_regions': patched,
              'remaining_encrypted': remaining, 'unverified_macho': unverified, 'macho_count': macho_count,
              'dump_verified': bool(patched), 'fully_decrypted': False,
              'export_status': 'runtime_regions_verified' if patched else 'application_copy_only',
              'skipped_symlinks': copied.get('skipped_symlinks', []),
              'parts': parts, 'ipa_sha256': archive_sha256,
              'note': '仅验证列出的运行架构/已加载模块区域及磁盘回读；头部归零、无剩余加密标志或目录复制均不证明完整脱壳。未加载模块、扩展和其他架构需单独验证；原签名已可能失效。多分片按编号拼接，不恢复原始源码。'}
    job.artifact('dump-manifest.json', result)
    return result


def api_check(job, args):
    parsed=urlsplit(args['url'])
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('url 必须是无内嵌凭据的 HTTP(S) URL')
    identities=[('baseline',{})]
    if args.get('headers'): identities.append(('provided_identity',args['headers']))
    if args.get('compare_headers'): identities.append(('comparison_identity',args['compare_headers']))
    # Preserve explicit protocol headers in the baseline (e.g. Content-Type).
    # Validate the entire comparison before emitting even the first request.
    base=args.get('base_headers',{})
    for headers in [base]+[headers for _,headers in identities]:
        for key,value in headers.items():
            if '\n' in key+value or '\r' in key+value:
                raise ValueError('请求头不允许换行')
    requests=[]
    for label,identity in identities:
        headers=httpx.Headers(base)
        headers.update(identity)  # HTTP header names are case-insensitive.
        requests.append((label,headers))
    job.update(stage='request_comparison')
    samples=[]
    for label,headers in requests:
        job.check()
        with httpx.Client(timeout=20,verify=True,follow_redirects=False,trust_env=False) as client:
            with client.stream(args.get('method','GET'),args['url'],headers=headers,content=args.get('body','')) as response:
                data=bytearray()
                truncated=False
                for chunk in response.iter_bytes():
                    job.check()
                    if len(data)+len(chunk)>1024*1024:
                        data.extend(chunk[:1024*1024-len(data)]);truncated=True;break
                    data.extend(chunk)
                sample={'identity':label,'status':response.status_code,'bytes_sampled':len(data),'truncated':truncated,
                        'sha256':hashlib.sha256(data).hexdigest(),
                        'response_headers':{k:('[redacted]' if k.lower() in ('set-cookie','authorization') else v) for k,v in response.headers.items()},
                        'body_preview':data[:4096].decode('utf-8','replace')}
                samples.append(sample)
                job.artifact('response-'+label+'.json',sample)
    result={'url':args['url'],'method':args.get('method','GET'),'samples':samples,
            'candidate_only':True,'confirmed_vulnerability':False,
            'interpretation':'基线使用显式base_headers；各身份仅覆盖自己的请求头，方法和正文共用。基线请求头、URL/正文仍可能含身份字段，不能自动等同匿名。状态码/响应相似只是线索，需验证资源归属、角色权限和业务预期。未自动跟随跳转。'}
    job.artifact('api-comparison.json',result)
    return result


def proxy(job,device,args):
    command=shutil.which('mitmdump')
    if not command: raise RuntimeError('镜像内缺少 mitmdump')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    output=job.out/'http-flows.jsonl'
    atomic_json(job.work/'rules.json',[])
    env={k:v for k,v in os.environ.items() if not k.startswith('PLUGIN_SSH_')}
    env.update(IOS_PROXY_WORK=str(job.work),IOS_PROXY_OUTPUT=str(output))
    conf=job.manager.data.parent/'proxy-ca'
    conf.mkdir(exist_ok=True,mode=0o700)
    proc=subprocess.Popen([command,'--listen-host','127.0.0.1','--listen-port',str(port),
                           '--set',f'confdir={conf}','--set','stream_large_bodies=1m',
                           '--set','body_size_limit=16m','--set','termlog_verbosity=error',
                           '-s',str(HERE/'proxy_addon.py')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env)
    try:
        for _ in range(100):
            job.check()
            if proc.poll() is not None: raise RuntimeError('代理启动失败')
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.1): break
            except OSError: time.sleep(.1)
        else: raise RuntimeError('代理启动超时')
        ca=conf/'mitmproxy-ca-cert.pem'
        if ca.exists(): job.artifact('proxy-ca-cert.pem',ca.read_bytes())
        with device.reverse(port) as remote_port:
            job.update(stage='capturing',connection={'device_proxy_host':'127.0.0.1','device_proxy_port':remote_port,
                        'note':'SSH 隧道已建立；设备/App 必须使用此代理。HTTPS 需要信任本插件 CA；固定证书或自定义网络栈需对应 Hook。未更改设备代理设置。'})
            deadline=time.monotonic()+args.get('duration',120)
            while time.monotonic()<deadline:
                job.check()
                if proc.poll() is not None: raise RuntimeError('代理进程异常退出')
                time.sleep(.2)
    finally:
        terminate(proc)
        if output.exists(): job.register(output.name)
    count=sum(1 for _ in output.open()) if output.exists() else 0
    return {'captured_flows':count,'coverage':'仅经此代理的 HTTP(S)；0 条流量不表示目标没有通信'}
