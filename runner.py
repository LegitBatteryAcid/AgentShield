"""Process supervisor used by the desktop and integration tests."""
import json
import subprocess
import sys
import threading
import time

from broker import Broker
from config import ROOT
from security import SecurityViolation
from mail_ai import review_email
from gemini_client import api_session


class AgentRun:
    def __init__(self, pc, mail, callback):
        self.pc, self.mail, self.callback = pc, mail, callback
        self.process = None
        self.thread = None
        self.cancelled = threading.Event()
        self.broker = Broker(pc, mail, self.emit)
        self.terminal = False
        self.lock = threading.RLock()
        self.worker_command = [sys.executable, '-u', str(ROOT / 'agent.py')]

    def emit(self, event, **data):
        self.callback(dict(event=event, mail_id=self.mail['id'], **data))

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        with self.lock:
            self.cancelled.set()
            self.kill()

    def kill(self):
        if self.process and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)

    def quarantine(self, error, tool):
        self.kill()
        incident = self.broker.incident or dict(reason=str(error), tool=tool,
            target='', evidence='policy check', secrets=[], secret_bytes_delivered=0)
        incident.update(process_terminated=self.process.poll() is not None,
                        pid=self.process.pid, exit_code=self.process.returncode)
        self.pc.quarantine(self.mail, incident)
        self.terminal = True
        self.emit('quarantined', incident=incident)

    def run(self):
        timer = threading.Timer(160, self.stop)
        try:
            if len(self.mail['body']) > 60000:
                raise RuntimeError('Email exceeds 60,000 characters.')
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            with self.lock:
                if self.cancelled.is_set():
                    return
                self.process = subprocess.Popen(self.worker_command,
                    cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    text=True, encoding='utf-8', creationflags=flags)
            timer.start()
            self.emit('process', pid=self.process.pid)
            self.mail.update(status='checking', error='')
            self.pc.save()
            self.emit('checking', reason='Security Gemini is inspecting the email; summariser is waiting.')
            with api_session(lambda event: self.emit(event['event'], **{k: v for k, v in event.items() if k != 'event'})):
                verdict = review_email(self.pc, self.mail)
            if self.cancelled.is_set():
                raise RuntimeError('Processing interrupted; email held for retry.')
            self.mail['security_review'] = verdict
            self.pc.save()
            self.emit('security_review', verdict=verdict)
            try:
                self.broker.inspect_email()
            except SecurityViolation as error:
                self.quarantine(error, 'email_text_check')
                return
            if verdict['verdict'] == 'malicious':
                try:
                    self.broker.reject_review(verdict['reason'])
                except SecurityViolation as error:
                    self.quarantine(error, 'security_review')
                    return
            self.mail['status'] = 'summarising'
            self.pc.save()
            self.emit('summarising', reason='Security approved. Summarising with a separate Gemini conversation.')
            self.process.stdin.write(json.dumps(dict(
                mail={key: self.mail[key] for key in ('subject', 'body', 'sender')},
                public_files=self.pc.public_files())) + '\n')
            self.process.stdin.flush()
            for line in self.process.stdout:
                if self.cancelled.is_set():
                    break
                if len(line) > 200000:
                    raise RuntimeError('Agent output exceeded the size limit.')
                event = json.loads(line)
                if event['event'] == 'tool':
                    try:
                        result = self.broker.dispatch(event.get('name'), event.get('args'))
                    except SecurityViolation as error:
                        self.quarantine(error, event.get('name'))
                        break
                    self.process.stdin.write(json.dumps({'ok': True, 'result': result}) + '\n')
                    self.process.stdin.flush()
                elif event['event'] == 'complete':
                    self.pc.summarised(self.mail, event['summary'])
                    self.terminal = True
                    self.emit('complete', summary=event['summary'])
                    break
                elif event['event'] == 'error':
                    failure = RuntimeError(event['message'])
                    failure.retry_after = event.get('retry_after', 60)
                    raise failure
                else:
                    self.emit(event['event'], **{k: v for k, v in event.items() if k != 'event'})
            if not self.terminal:
                raise RuntimeError('Agent stopped by time limit or shutdown.' if self.cancelled.is_set()
                          else 'Agent exited without completing the task.')
        except Exception as error:
            message = str(error) if isinstance(error, RuntimeError) else type(error).__name__ + ': connection or processing failed'
            self.mail['attempts'] = self.mail.get('attempts', 0) + 1
            delay = max(min(300, 60 * 2 ** min(self.mail['attempts'] - 1, 3)),
                        min(86400, getattr(error, 'retry_after', 0)))
            self.mail.update(status='waiting_retry', error=message, retry_at=time.time() + delay)
            self.pc.save()
            self.emit('error', message=message, retry_seconds=delay)
        finally:
            timer.cancel()
            self.kill()
            if self.process:
                for stream in (self.process.stdin, self.process.stdout):
                    if stream:
                        try:
                            stream.close()
                        except OSError:
                            # A reaped worker can leave a broken pipe on Windows.
                            pass
            self.emit('finished')
