"""Offline dump verification fixtures: real Mach-O bytes, no Frida/device calls."""
import ast
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from static_analysis import inspect_macho


def load_operations():
    # Compile these production functions verbatim, avoiding unrelated HTTP deps.
    tree = ast.parse((ROOT / 'operations.py').read_text())
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                and node.name in ('app_for', 'binary_slice', 'dump')]
    module = types.ModuleType('dump_functions_under_test')
    module.__dict__.update(Path=Path, struct=struct, re=re, hashlib=hashlib,
                           zipfile=zipfile, inspect_macho=inspect_macho)
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(ROOT / 'operations.py'), 'exec'), module.__dict__)
    return module


def load_worker():
    fake = types.ModuleType('frida')
    fake.__version__ = 'fixture'
    spec = importlib.util.spec_from_file_location('worker_under_test', ROOT / 'frida_worker.py')
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {'frida': fake}):
        spec.loader.exec_module(module)
    return module


def binary(bits=64, cryptid=1, uuid=b'fixture-uuid-123'):
    assert len(uuid) == 16
    cpu = 0x0100000C if bits == 64 else 12
    base = 0x100000000 if bits == 64 else 0x1000
    def segment(name, vmaddr, fileoff):
        if bits == 64:
            return struct.pack('<II16sQQQQiiII', 0x19, 72, name, vmaddr, 512, fileoff, 512, 7, 5, 0, 0)
        return struct.pack('<II16sIIIIiiII', 1, 56, name, vmaddr, 512, fileoff, 512, 7, 5, 0, 0)
    commands = [segment(b'__TEXT', base, 0), segment(b'__CODE', base + 0x4000, 512),
                struct.pack('<II16s', 0x1b, 24, uuid)]
    encryption = struct.pack('<IIIII', 0x2c if bits == 64 else 0x21, 24 if bits == 64 else 20, 544, 32, cryptid)
    if bits == 64:
        encryption += b'\0' * 4
    commands.append(encryption)
    header = struct.pack('<IIIIIII', 0xfeedfacf if bits == 64 else 0xfeedface, cpu, 0, 2, len(commands), sum(map(len, commands)), 0)
    if bits == 64:
        header += b'\0' * 4
    result = header + b''.join(commands)
    result += b'\0' * (1024 - len(result))
    return result[:544] + b'C' * 32 + result[576:]


def fat_binary(slices, endian='>', width=32):
    size = 32 if width == 64 else 20
    offset = 8 + len(slices) * size
    entries = []
    for value in slices:
        cpu, subtype = struct.unpack_from('<II', value, 4)
        fields = (cpu, subtype, offset, len(value), 0)
        entries.append(struct.pack(endian + ('IIQQII' if width == 64 else 'IIIII'), *(fields + (0,) if width == 64 else fields)))
        offset += len(value)
    return struct.pack(endian + 'II', 0xcafebabf if width == 64 else 0xcafebabe, len(slices)) + b''.join(entries + slices)


class Job:
    def __init__(self, root):
        self.work, self.out = root / 'work', root / 'out'
        self.work.mkdir()
        self.out.mkdir()
    def check(self):
        pass
    def update(self, **kwargs):
        pass
    def artifact(self, name, value):
        raw = json.dumps(value).encode() if isinstance(value, dict) else value
        (self.out / name).write_bytes(raw)
        return name


class Device:
    def __init__(self, source):
        self.source = source
    def apps(self):
        return [{'bundle_id': 'fixture.app', 'path': '/private/var/containers/Fixture.app'}]
    def download_tree(self, remote, local, cancel):
        shutil.copytree(self.source, local)
        return {'skipped_symlinks': [], 'bytes': sum(p.stat().st_size for p in self.source.rglob('*') if p.is_file())}


class DumpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.dump-tests-', dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ops, self.worker = load_operations(), load_worker()
        self.worker.CANCELLED.clear()

    def record(self, data, path='/var/containers/Fixture.app/Fixture'):
        cpu, subtype = struct.unpack_from('<II', data, 4)
        meta = self.ops.binary_slice(io.BytesIO(data), cpu, subtype)
        return dict(meta['encryption'][0], path=path, base='0x200000000' if meta['bits'] == 64 else '0x20000000',
                    cpu=cpu, subtype=subtype, bits=meta['bits'], uuid=meta['uuid'],
                    segments=[{k: (v if k == 'name' else str(v)) for k, v in s.items()} for s in meta['segments']],
                    file='region-0.bin', sha256=hashlib.sha256(b'P' * 32).hexdigest())

    def run_dump(self, data, records, payload=b'P' * 32):
        source = self.root / 'Fixture.app'
        source.mkdir(exist_ok=True)
        (source / 'Fixture').write_bytes(data)
        job = Job(self.root)
        @contextlib.contextmanager
        def connection(*args):
            yield 'fixture-python', 'fixture-address', {}
        def worker(job, python, request):
            (job.work / 'region-0.bin').write_bytes(payload)
            return {'regions': records}
        with patch.object(self.ops, 'frida_connection', connection, create=True), patch.object(self.ops, 'worker', worker, create=True):
            result = self.ops.dump(job, Device(source), {'bundle_id': 'fixture.app'})
        return result, job

    def test_parser_and_nonidentity_segment_mapping_32_and_64(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                data = binary(bits)
                record = self.record(data)
                chunks = list(self.worker.mapped_chunks(record))
                base = int(record['base'], 16)
                self.assertEqual(chunks, [(base + 0x4020, 32)])
                self.assertNotEqual(chunks[0][0], base + record['cryptoff'])

    @unittest.skipUnless(shutil.which('node'), 'Node not available for embedded JavaScript fixture')
    def test_actual_dump_javascript_parses_binary_fixture(self):
        raw = binary()
        script = r'''
const image=Buffer.from(process.argv[1],'base64');
const moduleBase=0x200000000n;
function physical(address, length) {
  let offset=address-moduleBase;
  if(offset>=0x4000n && offset<0x4200n) offset=offset-0x4000n+512n;
  offset=Number(offset);
  if(offset<0 || offset+length>image.length) throw new Error('fixture memory access');
  return image.subarray(offset,offset+length);
}
class Pointer {
  constructor(value) { this.value=BigInt(value); }
  add(value) { return new Pointer(this.value+BigInt(value)); }
  toString() { return '0x'+this.value.toString(16); }
  readU32() { return physical(this.value,4).readUInt32LE(); }
  readU64() { return physical(this.value,8).readBigUInt64LE(); }
  readUtf8String(length) { return physical(this.value,length).toString('utf8'); }
  readByteArray(length) { const b=physical(this.value,length);return b.buffer.slice(b.byteOffset,b.byteOffset+b.length); }
}
const ptr=(value)=>new Pointer(value);
const Process={enumerateModules:()=>[{path:'/private/var/containers/Fixture.app/Fixture',base:new Pointer(moduleBase)}]};
const rpc={exports:{}};
'''
        script += self.worker.DUMP_SCRIPT
        script += "\nconsole.log(JSON.stringify(rpc.exports.modules('/var/containers/Fixture.app')));\n"
        result = subprocess.run(['node', '-e', script, base64.b64encode(raw).decode()], capture_output=True, text=True, check=True)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed['errors'], [])
        self.assertEqual(len(parsed['regions']), 1)
        record = parsed['regions'][0]
        expected = self.record(raw)
        for key in ('uuid', 'bits', 'cpu', 'subtype', 'cryptoff', 'cryptsize', 'cryptid_offset', 'segments'):
            self.assertEqual(record[key], expected[key])
        self.assertEqual(list(self.worker.mapped_chunks(record)), [(0x200004020, 32)])

    def test_cross_segment_mapping_and_unmapped_rejection(self):
        record = self.record(binary())
        record.update(cryptoff=500, cryptsize=24)
        base = int(record['base'], 16)
        self.assertEqual(list(self.worker.mapped_chunks(record)), [(base + 500, 12), (base + 0x4000, 12)])
        record.update(cryptoff=1020, cryptsize=16)
        with self.assertRaisesRegex(RuntimeError, 'no unique'):
            list(self.worker.mapped_chunks(record))

    def test_fat_slice_ranges_all_header_formats(self):
        for endian in ('<', '>'):
            for width in (32, 64):
                data = fat_binary([binary(32), binary(64)], endian, width)
                meta = self.ops.binary_slice(io.BytesIO(data), 0x0100000c, 0)
                self.assertEqual(meta['size'], 1024)
                self.assertGreater(meta['offset'], 1024)

    def test_verified_dump_reads_back_real_bytes_without_full_claim(self):
        data = binary()
        record = self.record(data)
        result, job = self.run_dump(data, [record])
        self.assertTrue(result['dump_verified'])
        self.assertFalse(result['fully_decrypted'])
        self.assertEqual(result['export_status'], 'runtime_regions_verified')
        self.assertFalse(result['remaining_encrypted'])
        self.assertEqual(result['verified_regions'][0]['sha256'], record['sha256'])
        with zipfile.ZipFile(job.out / 'application.ipa') as archive:
            patched = archive.read('Payload/Fixture.app/Fixture')
        expected = bytearray(data)
        expected[544:576] = b'P' * 32
        struct.pack_into('<I', expected, record['cryptid_offset'], 0)
        self.assertEqual(patched, bytes(expected))

    def test_no_regions_is_copy_only_even_if_header_is_clear(self):
        result, _ = self.run_dump(binary(cryptid=0), [])
        self.assertFalse(result['dump_verified'])
        self.assertFalse(result['fully_decrypted'])
        self.assertEqual(result['export_status'], 'application_copy_only')

    def test_invalid_macho_is_not_treated_as_clear(self):
        result, _ = self.run_dump(b'\xcf\xfa\xed\xfe', [])
        self.assertEqual(result['unverified_macho'], ['Fixture'])
        self.assertFalse(result['fully_decrypted'])

    def test_mismatch_uuid_rejected(self):
        data = binary()
        record = self.record(data)
        record['uuid'] = '0' * 32
        with self.assertRaisesRegex(ValueError, 'UUID'):
            self.run_dump(data, [record])

    def test_mismatch_segment_rejected(self):
        data = binary()
        record = self.record(data)
        record['segments'][1]['vmaddr'] = '1234'
        with self.assertRaisesRegex(ValueError, 'segment'):
            self.run_dump(data, [record])

    def test_mismatch_length_rejected_before_patch(self):
        data = binary()
        with self.assertRaisesRegex(ValueError, '长度'):
            self.run_dump(data, [self.record(data)], payload=b'P' * 31)

    def test_mismatch_hash_rejected_before_patch(self):
        data = binary()
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.run_dump(data, [self.record(data)], payload=b'X' * 32)

    def test_mismatch_encryption_command_rejected(self):
        data = binary()
        record = self.record(data)
        record['cryptid_offset'] += 4
        with self.assertRaisesRegex(ValueError, '加密命令'):
            self.run_dump(data, [record])

    def test_region_path_escape_rejected(self):
        data = binary()
        record = self.record(data, path='/var/containers/Fixture.app/../other')
        with self.assertRaisesRegex(ValueError, '越界'):
            self.run_dump(data, [record])

    def test_sigterm_during_spawn_reaches_finally_and_resumes(self):
        # Real local signal, isolated fake Frida API. No network or device access.
        script = r'''
import json,runpy,sys,time,types
class Device:
    def enumerate_processes(self): return []
    def enumerate_applications(self): return []
    def spawn(self, bundle):
        print(json.dumps({'fixture':'spawn-enter'}), flush=True)
        time.sleep(.3)
        return 42
    def resume(self, pid):
        print(json.dumps({'fixture_resumed':pid}), flush=True)
class Manager:
    def add_remote_device(self, address): return Device()
    def remove_remote_device(self, address): pass
f=types.ModuleType('frida');f.__version__='fixture';f.get_device_manager=lambda:Manager()
sys.modules['frida']=f
runpy.run_path(sys.argv[1],run_name='__main__')
'''
        proc = subprocess.Popen([sys.executable, '-u', '-c', script, str(ROOT / 'frida_worker.py')],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            proc.stdin.write(json.dumps({'action': 'hook', 'address': 'fixture', 'bundle_id': 'fixture', 'duration': 10}) + '\n')
            proc.stdin.flush()
            first = json.loads(proc.stdout.readline())
            self.assertEqual(first, {'fixture': 'spawn-enter'})
            proc.send_signal(signal.SIGTERM)
            output, error = proc.communicate(timeout=5)
            messages = [json.loads(line) for line in output.splitlines()]
            cleanup = next(m['cleanup'] for m in messages if 'cleanup' in m)
            self.assertTrue(cleanup['confirmed'])
            self.assertTrue(cleanup['resume_confirmed'])
            self.assertEqual(cleanup['pid'], 42)
            self.assertIn({'fixture_resumed': 42}, messages)
            self.assertTrue(any('cancelled' in m.get('error', '') for m in messages))
            self.assertEqual(proc.returncode, 1)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


if __name__ == '__main__':
    unittest.main()
