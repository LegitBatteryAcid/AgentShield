"""Clear during actual background work, using isolated mailboxes and test workers."""
from copy import deepcopy
import gc
from pathlib import Path
import sys
import threading
import time
import unittest
import uuid
from unittest.mock import patch

from dashboard import Desktop
from runner import AgentRun
from shadow import ShadowRun
from simulation import MiniPC, new_mail


class ClearTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).parent / ('run_' + uuid.uuid4().hex)
        self.directory.mkdir()
        self.pc = MiniPC(self.directory / 'pc.json')
        self.files = deepcopy(self.pc.state['files'])
        self.account = deepcopy(self.pc.state['account'])
        for folder in ('inbox', 'summaries', 'quarantine'):
            mail = new_mail('Test message', 'WAIT')
            mail.update(status='waiting_retry' if folder == 'inbox' else 'quarantined', retry_at=time.time() + 3600)
            self.pc.state[folder].append(mail)
        self.pc.state['links']['https://test.example.test'] = {}
        self.pc.save()
        self.release = threading.Event()
        with patch('dashboard.MiniPC', return_value=self.pc):
            self.app = Desktop()
        self.app.withdraw()

    def tearDown(self):
        self.release.set()
        self.app.close()
        self.app = None
        # Destroy Tk variables on the main thread before later worker tests run.
        gc.collect()
        for file in self.directory.iterdir():
            file.unlink()
        self.directory.rmdir()

    def pump(self, condition, timeout=5):
        deadline = time.monotonic() + timeout
        while not condition() and time.monotonic() < deadline:
            self.app.update()
            time.sleep(.01)
        self.assertTrue(condition(), 'UI operation did not finish')

    def assert_cleared(self):
        self.pump(lambda: not self.app.clearing)
        restored = MiniPC(self.pc.path)
        for folder in ('inbox', 'summaries', 'quarantine', 'incidents', 'investigations', 'links'):
            self.assertFalse(restored.state[folder], folder)
        self.assertEqual(restored.state['files'], self.files)
        self.assertEqual(restored.state['account'], self.account)
        self.assertFalse(self.app.table.get_children())
        self.assertEqual(self.app.status.get(), 'Cleared')
        self.assertEqual(str(self.app.clear_button['state']), 'normal')

    def test_idle_clear_button_empties_every_folder(self):
        self.app.clear_button.invoke()
        self.assert_cleared()

    def test_clear_accepts_request_during_generation_and_discards_late_email(self):
        entered = threading.Event()
        def generate(pc):
            entered.set()
            self.release.wait(5)
            pc.create_link(pc.public_files()[0]['path'])
            return new_mail('Late reply', 'Do not restore this')
        with patch('dashboard.create_email', side_effect=generate), patch('dashboard.AgentRun') as agent:
            self.app.compose()
            self.assertTrue(entered.wait(2))
            self.assertEqual(str(self.app.clear_button['state']), 'normal')
            self.app.clear_button.invoke()
            self.assertTrue(self.app.clearing)
            self.app.compose()
            self.app.start_next()
            agent.assert_not_called()
            self.release.set()
            self.assert_cleared()

    def test_late_generation_error_does_not_interrupt_clear(self):
        self.app.generating = True
        self.app.clear_button.invoke()
        with patch('dashboard.messagebox.showerror') as popup:
            self.app.events.put(dict(event='generation_error', message='Timed out'))
            self.assert_cleared()
            popup.assert_not_called()

    def test_clear_stops_agent_and_waits_for_security_request(self):
        entered = threading.Event()
        def review(*_args):
            entered.set()
            self.release.wait(5)
            return dict(verdict='safe', reason='Test', target_files=[])
        mail = self.pc.state['inbox'][0]
        run = AgentRun(self.pc, mail, self.app.events.put)
        run.worker_command = [sys.executable, '-u', str(Path(__file__).with_name('shadow_fixture.py'))]
        with patch('runner.review_email', side_effect=review):
            self.app.run_handle = run.start()
            self.assertTrue(entered.wait(2))
            self.app.clear_button.invoke()
            self.assertTrue(run.cancelled.is_set())
            self.assertIsNotNone(run.process.poll())
            self.assertTrue(self.app.clearing)
            self.release.set()
            self.assert_cleared()
            self.assertFalse(run.thread.is_alive())

    def test_clear_stops_shadow_and_removes_saved_partial_report(self):
        original_start = ShadowRun.start
        def fixture_start(run):
            run.worker_command = [sys.executable, '-u', str(Path(__file__).with_name('shadow_fixture.py'))]
            return original_start(run)
        self.app.show_folder('quarantine')
        with patch('shadow_view.ShadowRun.start', fixture_start):
            self.app.investigate()
        run = self.app.investigation.run_handle
        self.pump(lambda: run.process is not None)
        self.app.clear_button.invoke()
        self.assert_cleared()
        self.assertIsNone(self.app.investigation)
        self.assertFalse(run.thread.is_alive())
        self.assertIsNotNone(run.process.poll())


if __name__ == '__main__':
    unittest.main()
