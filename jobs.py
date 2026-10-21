"""Bounded, cancellable jobs shared by MCP and the plugin UI."""
import json
import os
from pathlib import Path
import re
import shutil
import threading
import time
import uuid


class Cancelled(Exception):
    pass


def scrub(value):
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, str):
        for key in ('SSH_PASSWORD', 'SSH_PRIVATE_KEY', 'SSH_KEY_PASSPHRASE'):
            secret = os.environ.get('PLUGIN_' + key, '')
            if secret:
                value = value.replace(secret, '[redacted]')
        return value
    return value


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.new')
    temp.write_text(json.dumps(scrub(value), ensure_ascii=False, indent=2), encoding='utf-8')
    temp.chmod(0o600)
    temp.replace(path)


class Job:
    def __init__(self, manager, kind, group):
        self.manager = manager
        self.id = 'run-' + time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:12]
        self.stop = threading.Event()
        self.lock = threading.RLock()
        self.group = group
        self.out = manager.artifacts / self.id
        self.work = manager.data / self.id
        self.out.mkdir(mode=0o700)
        self.work.mkdir(mode=0o700)
        self.state = dict(job_id=self.id, kind=kind, status='running', stage='starting',
                          created_at=time.time(), updated_at=time.time(), artifacts=[], result=None, error=None)

    def check(self):
        if self.stop.is_set():
            raise Cancelled('任务已停止')
        if time.time() - self.state['created_at'] > 1800:
            raise Cancelled('达到任务最长运行时间 1800 秒')

    def update(self, **values):
        with self.lock:
            self.state.update(scrub(values), updated_at=time.time())
            atomic_json(self.work / 'state.json', self.state)

    def view(self):
        with self.lock:
            return json.loads(json.dumps(self.state))

    def artifact(self, name, value):
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', name):
            raise ValueError('Invalid artifact name')
        path = self.out / name
        if isinstance(value, (dict, list)):
            if len(json.dumps(scrub(value), ensure_ascii=False, indent=2).encode('utf-8')) > 50 * 1024 * 1024:
                raise ValueError('产物超过 50MB')
            atomic_json(path, value)
        else:
            raw = scrub(value).encode('utf-8') if isinstance(value, str) else value
            if len(raw) > 50 * 1024 * 1024:
                raise ValueError('产物超过 50MB')
            path.write_bytes(raw)
            path.chmod(0o600)
        return self.register(name)

    def register(self, name):
        path = self.out / name
        if path.parent != self.out or path.is_symlink() or not path.is_file() or path.stat().st_size > 50 * 1024 * 1024:
            raise ValueError('无效或过大的产物')
        rel = self.id + '/' + name
        with self.lock:
            if rel not in self.state['artifacts']:
                self.state['artifacts'].append(rel)
            self.update()
        return rel


class Jobs:
    def __init__(self, data, artifacts):
        self.data, self.artifacts = Path(data) / 'jobs', Path(artifacts)
        self.data.mkdir(parents=True, exist_ok=True)
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.running = {}
        # A restart cannot resume an SSH session or a Frida hook.
        for path in self.data.glob('run-*/state.json'):
            try:
                state = json.loads(path.read_text())
                if state['status'] in ('running', 'stopping'):
                    state.update(status='interrupted', error='插件重启，连接与运行任务已中断；请重新启动任务')
                    atomic_json(path, state)
                self.clean_work(path.parent)
            except (OSError, ValueError, KeyError):
                pass

    def start(self, kind, callback, group='device'):
        with self.lock:
            active = [j for j in self.running.values() if j.state['status'] in ('running', 'stopping')]
            if len(active) >= 3 or any(j.group == group for j in active):
                raise ValueError('已有同类任务正在运行，请等待或停止该任务')
            if len(list(self.data.glob('run-*/state.json'))) >= 100:
                raise ValueError('已保留 100 个任务，请先使用 ios_job_delete 清理旧任务')
            job = Job(self, kind, group)
            self.running[job.id] = job
            job.update()
            thread = threading.Thread(target=self._run, args=(job, callback), daemon=True)
            thread.start()
            return job.view()

    def _run(self, job, callback):
        final = {}
        try:
            result = callback(job)
            job.check()
            final = dict(status='completed', stage='finished', result=result)
        except Cancelled as exc:
            final = dict(status='cancelled', stage='stopped', error=str(exc))
        except Exception as exc:
            # Errors are bounded; no traceback or credentials enter tool output.
            final = dict(status='failed', stage='failed', error=scrub(str(exc))[:1200])
        finally:
            try:
                job.update(stage='finalizing')
                job.artifact('task.json', {**job.view(), **final})
            except Exception:
                final=dict(status='failed',stage='failed',error='任务报告无法写入，请检查插件磁盘空间')
            finally:
                try: self.clean_work(job.work)
                except OSError:
                    final=dict(status='failed',stage='cleanup_pending',error='临时文件清理失败；重启时会再清理')
                job.update(**final)

    @staticmethod
    def clean_work(directory):
        for item in directory.iterdir():
            if item.name=='state.json': continue
            if item.is_dir() and not item.is_symlink(): shutil.rmtree(item)
            else: item.unlink(missing_ok=True)

    def get(self, job_id):
        if not re.fullmatch(r'run-[0-9]{8}-[0-9]{6}-[a-f0-9]{12}', job_id):
            raise ValueError('任务编号无效')
        with self.lock:
            if job_id in self.running:
                return self.running[job_id].view()
        path = self.data / job_id / 'state.json'
        if not path.exists():
            raise ValueError('任务不存在')
        return json.loads(path.read_text())

    def list(self):
        return sorted([self.get(p.parent.name) for p in self.data.glob('run-*/state.json')],
                      key=lambda j: j['created_at'], reverse=True)

    def cancel(self, job_id):
        state = self.get(job_id)
        with self.lock:
            job = self.running.get(job_id)
            if job and state['status'] == 'running':
                job.update(status='stopping', stage='cleaning_up')
                job.stop.set()
                return job.view()
        return state

    def busy(self):
        return any(j.state['status'] in ('running', 'stopping') for j in self.running.values())

    def shutdown(self):
        for job in self.running.values():
            job.stop.set()

    def delete(self, job_id):
        import shutil
        state = self.get(job_id)
        if state['status'] in ('running', 'stopping'):
            raise ValueError('运行中的任务不可删除')
        with self.lock:
            self.running.pop(job_id, None)
            shutil.rmtree(self.data / job_id)
            shutil.rmtree(self.artifacts / job_id, ignore_errors=True)
        return {'deleted': job_id}
