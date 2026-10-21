"""An isolated Frida runtime. One request on stdin, bounded JSON events on stdout."""
import base64
import hashlib
import json
from pathlib import Path
import signal
import sys
import threading
import time
import frida

CANCELLED = threading.Event()
OUTPUT_LOCK = threading.Lock()


def check_cancelled():
    if CANCELLED.is_set():
        raise RuntimeError('Frida worker cancelled')


def output(value):
    line = json.dumps(value, ensure_ascii=False)
    if len(line.encode('utf-8')) > 240 * 1024:
        raise RuntimeError('Frida result exceeds bounded IPC message size')
    with OUTPUT_LOCK:
        sys.stdout.write(line + '\n')
        sys.stdout.flush()


DUMP_SCRIPT = r'''
rpc.exports = {
  modules(appPath) {
    const out=[], errors=[];
    const canonical=(p)=>p.startsWith('/private/var/') ? p.slice(8) : p;
    const root=canonical(appPath).replace(/\/$/,'')+'/';
    for(const m of Process.enumerateModules()) {
      if(!canonical(m.path).startsWith(root)) continue;
      try {
        const magic=m.base.readU32();
        if(magic!==0xfeedfacf && magic!==0xfeedface) throw new Error('unsupported loaded Mach-O magic');
        const bits=magic===0xfeedfacf?64:32, header=bits===64?32:28;
        const n=m.base.add(16).readU32(), commandBytes=m.base.add(20).readU32();
        if(n>4096 || commandBytes>16*1024*1024 || n*8>commandBytes) throw new Error('invalid loaded command region');
        let p=m.base.add(header), used=0, uuid=null;
        const segments=[], encryption=[];
        const u64=(address)=>address.readU64().toString();
        for(let i=0;i<n;i++) {
          if(used+8>commandBytes) throw new Error('truncated loaded command');
          const cmd=p.readU32(),size=p.add(4).readU32();
          if(size<8 || size%4 || used+size>commandBytes) throw new Error('invalid loaded command size');
          if(cmd===0x21 || cmd===0x2c) {
            if(size<(cmd===0x2c?24:20)) throw new Error('truncated loaded encryption command');
            const offset=p.add(8).readU32(),length=p.add(12).readU32(),id=p.add(16).readU32();
            if(id && length) encryption.push({cryptoff:offset,cryptsize:length,original_cryptid:id,cryptid_offset:header+used+16});
          } else if(cmd===0x1b) {
            if(size!==24 || uuid!==null) throw new Error('invalid loaded UUID command');
            uuid=Array.from(new Uint8Array(p.add(8).readByteArray(16)),(x)=>x.toString(16).padStart(2,'0')).join('');
          } else if(cmd===1 || cmd===0x19) {
            const is64=cmd===0x19, minimum=is64?72:56;
            if(size<minimum || segments.length>=128) throw new Error('invalid loaded segment');
            const nsects=p.add(is64?64:48).readU32();
            if(minimum+nsects*(is64?80:68)>size) throw new Error('invalid loaded section count');
            const value=(off)=>is64?u64(p.add(off)):String(p.add(off).readU32());
            segments.push({name:p.add(8).readUtf8String(16).replace(/\0.*$/,''),
              vmaddr:value(24),vmsize:value(is64?32:28),fileoff:value(is64?40:32),filesize:value(is64?48:36)});
          }
          p=p.add(size);used+=size;
        }
        if(used!==commandBytes) throw new Error('loaded command count mismatch');
        if(encryption.length && !uuid) throw new Error('encrypted loaded module lacks UUID');
        for(const region of encryption) out.push(Object.assign({path:m.path,base:m.base.toString(),bits,
          cpu:m.base.add(4).readU32(),subtype:m.base.add(8).readU32(),uuid,segments},region));
        if(out.length>512) throw new Error('loaded encryption region limit');
      }catch(e){errors.push({path:m.path,message:String(e).slice(0,300)});}
    }
    return {regions:out,errors};
  },
  read(address,length) {if(length>1048576) throw new Error('chunk too large');return ptr(address).readByteArray(length);}
};
'''


def mapped_chunks(record):
    """Map a file encryption range into runtime addresses using Mach-O segments."""
    segments = []
    for raw in record['segments']:
        segment = {key: int(raw[key]) for key in ('vmaddr', 'vmsize', 'fileoff', 'filesize')}
        if any(value < 0 for value in segment.values()) or segment['filesize'] > segment['vmsize']:
            raise RuntimeError('invalid loaded segment range')
        segments.append(segment)
    headers = [s for s in segments if s['fileoff'] == 0 and s['filesize'] >= (32 if record['bits'] == 64 else 28)]
    if len(headers) != 1:
        raise RuntimeError('loaded module has ambiguous header mapping')
    base, header_vmaddr = int(record['base'], 16), headers[0]['vmaddr']
    cursor, end = record['cryptoff'], record['cryptoff'] + record['cryptsize']
    if cursor < 0 or not 0 < record['cryptsize'] <= 128 * 1024 * 1024:
        raise RuntimeError('invalid loaded encryption range')
    while cursor < end:
        matches = [s for s in segments if s['fileoff'] <= cursor < s['fileoff'] + s['filesize']]
        if len(matches) != 1:
            raise RuntimeError('encrypted file offset has no unique loaded segment mapping')
        segment = matches[0]
        size = min(1024 * 1024, end - cursor, segment['fileoff'] + segment['filesize'] - cursor)
        address = base + segment['vmaddr'] - header_vmaddr + cursor - segment['fileoff']
        if address < 0 or address + size > 1 << record['bits']:
            raise RuntimeError('mapped runtime address overflow')
        yield address, size
        cursor += size


def main(args):
    manager = frida.get_device_manager()
    device = session = script = pid = None
    spawned = resumed = False
    detached = threading.Event()
    try:
        check_cancelled()
        device = manager.add_remote_device(args['address'])
        device.enumerate_processes()  # Complete a real protocol exchange before reporting ready.
        check_cancelled()
        if args['action'] == 'probe':
            return {'runtime': frida.__version__, 'reachable': True,
                    'application_count': len(device.enumerate_applications())}
        bundle = args['bundle_id']
        app = next((a for a in device.enumerate_applications() if a.identifier == bundle), None)
        check_cancelled()
        if app and app.pid:
            pid = app.pid
        else:
            # SIGTERM only sets an event: it cannot interrupt assignment of a returned pid.
            pid = device.spawn([bundle])
            spawned = True
            output({'spawned': True, 'pid': pid})
        check_cancelled()
        session = device.attach(pid)
        check_cancelled()
        session.on('detached', lambda *unused: detached.set())
        if args['action'] == 'hook':
            opts = {k: args.get(k, '') for k in ('profile', 'replace_from', 'replace_to')}
            opts.update(from_bytes=list(opts['replace_from'].encode()), to_bytes=list(opts['replace_to'].encode()))
            source = Path(__file__).with_name('hooks.js').read_text().replace('__OPTIONS__', json.dumps(opts))
        else:
            source = DUMP_SCRIPT
        script = session.create_script(source)
        def message(message, data):
            if message['type'] == 'send':
                item = message['payload']
                if data:
                    item['data_base64'] = base64.b64encode(data).decode()
                output({'event': item})
            elif message['type'] == 'error':
                output({'event': {'type': 'script_error', 'message': message.get('description', '')[:500]}})
        script.on('message', message)
        script.load()
        check_cancelled()
        if spawned:
            device.resume(pid)
            resumed = True
        output({'ready': True, 'runtime': frida.__version__, 'pid': pid, 'spawned': spawned})
        if args['action'] == 'hook':
            deadline = time.monotonic() + args['duration']
            while time.monotonic() < deadline and not detached.wait(.2):
                check_cancelled()
            if detached.is_set():
                raise RuntimeError('目标进程已退出或注入连接中断')
            stats = script.exports_sync.stats()
            if not stats['installed_hooks']:
                raise RuntimeError('当前应用没有找到此配置支持的 Hook 点；未完成动态覆盖')
            return dict(stats, runtime=frida.__version__, pid=pid,
                        coverage='仅列出的函数；无事件不代表无网络、无加密或无漏洞')
        if CANCELLED.wait(1):
            check_cancelled()
        observed = script.exports_sync.modules(args['app_path'])
        if observed['errors']:
            raise RuntimeError('应用模块头部无法验证: ' + json.dumps(observed['errors'], ensure_ascii=False)[:1200])
        records = observed['regions']
        if len(records) > 512:
            raise RuntimeError('加密区域数量超过限制')
        total = 0
        for i, record in enumerate(records):
            check_cancelled()
            total += record['cryptsize']
            if record['cryptsize'] > 128 * 1024 * 1024 or total > 512 * 1024 * 1024:
                raise RuntimeError('加密区域超过导出限制')
            dest = Path(args['output']) / ('region-' + str(i) + '.bin')
            digest = hashlib.sha256()
            with dest.open('xb') as stream:
                done = 0
                for address, size in mapped_chunks(record):
                    check_cancelled()
                    block = script.exports_sync.read(hex(address), size)
                    if len(block) != size:
                        raise RuntimeError('运行时读取长度不匹配')
                    stream.write(block)
                    digest.update(block)
                    done += size
                if done != record['cryptsize']:
                    raise RuntimeError('运行时区域长度不匹配')
            record['file'] = dest.name
            record['sha256'] = digest.hexdigest()
        return {'regions': records, 'runtime': frida.__version__, 'pid': pid,
                'note': '只导出当前进程已加载的应用模块；未运行扩展需要单独验证'}
    finally:
        cleanup = {'type': 'worker_cleanup', 'pid': pid, 'spawned': spawned,
                   'resume_confirmed': resumed if spawned else None, 'script_unloaded': script is None,
                   'session_detached': session is None, 'remote_removed': device is None, 'errors': []}
        if spawned and not resumed and pid is not None:
            try:
                device.resume(pid)
                cleanup['resume_confirmed'] = True
            except Exception as exc:
                cleanup['errors'].append('resume: ' + str(exc)[:150])
        if script:
            try:
                script.unload()
                cleanup['script_unloaded'] = True
            except Exception as exc:
                cleanup['errors'].append('unload: ' + str(exc)[:150])
        if session:
            try:
                session.detach()
                cleanup['session_detached'] = True
            except Exception as exc:
                cleanup['errors'].append('detach: ' + str(exc)[:150])
        if device:
            try:
                manager.remove_remote_device(args['address'])
                cleanup['remote_removed'] = True
            except Exception as exc:
                cleanup['errors'].append('remote removal: ' + str(exc)[:150])
        cleanup['confirmed'] = not cleanup['errors']
        output({'cleanup': cleanup})


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: CANCELLED.set())
    signal.signal(signal.SIGINT, lambda *_: CANCELLED.set())
    try:
        output({'result': main(json.loads(sys.stdin.readline()))})
    except Exception as error:
        output({'error': str(error)[:1000], 'runtime': frida.__version__})
        sys.exit(1)
