import io
import json
import ssl
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from gemini_client import generate, generate_json, api_session, ModelSession, TransientFailure, DEFAULT_SYSTEM


CONFIG = dict(GEMINI_API_KEY='fixture-primary-key', GEMINI_MODEL='gemini-3.1-flash-lite',
              GEMINI_FALLBACK_MODEL='gemini-3.5-flash-lite', GEMINI_BACKUP_API_KEY='', GEMINI_TIMEOUT_SECONDS='25')


def response(content=None, finish='STOP', raw=None):
    content = content or dict(role='model', parts=[dict(text='A useful summary.')])
    result = Mock()
    result.__enter__ = Mock(return_value=result)
    result.__exit__ = Mock(return_value=False)
    result.read.return_value = raw if raw is not None else json.dumps(dict(candidates=[dict(content=content, finishReason=finish)])).encode()
    return result


def http_error(code, retry_delay='60s'):
    body = json.dumps(dict(error=dict(message='Fixture message', details=[dict(retryDelay=retry_delay)]))).encode()
    return HTTPError('https://generativelanguage.googleapis.com/', code, 'fixture', {}, io.BytesIO(body))


class FailoverTests(unittest.TestCase):
    def setUp(self):
        self.config = dict(CONFIG)
        self.settings = patch('gemini_client.settings', side_effect=lambda: self.config).start()
        patch('gemini_client.time.sleep').start()
        self.opener = Mock()
        patch('gemini_client.build_opener', return_value=self.opener).start()
        self.addCleanup(patch.stopall)
        self.contents = [dict(role='user', parts=[dict(text='Summarise this fictional note.')])]

    def test_success_makes_only_one_request(self):
        self.opener.open.return_value = response()
        generate(self.contents)
        self.assertEqual(self.opener.open.call_count, 1)
        self.assertEqual(self.opener.open.call_args.kwargs['timeout'], 25)

    def test_timeout_switches_model_and_retains_schema_and_security_prompt(self):
        content = dict(role='model', parts=[dict(text='{"verdict":"malicious"}')])
        self.opener.open.side_effect = [TimeoutError('fixture-primary-key must not leak'), response(content)]
        events = []
        schema = dict(type='OBJECT', properties=dict(verdict=dict(type='STRING')))
        with api_session(events.append):
            result = generate_json('Independent security policy', dict(email='Fixture'), schema)
        self.assertEqual(result['verdict'], 'malicious')
        calls = self.opener.open.call_args_list
        self.assertIn('gemini-3.1-flash-lite', calls[0].args[0].full_url)
        self.assertIn('gemini-3.5-flash-lite', calls[1].args[0].full_url)
        for call in calls:
            payload = json.loads(call.args[0].data)
            self.assertEqual(payload['systemInstruction']['parts'][0]['text'], 'Independent security policy')
            self.assertEqual(payload['generationConfig']['responseSchema'], schema)
            self.assertNotIn('tools', payload)
        self.assertEqual([e['phase'] for e in events], ['fallback', 'recovered'])
        self.assertNotIn(self.config['GEMINI_API_KEY'], json.dumps(events))

    def test_wrapped_timeout_and_connection_reset_also_fail_over(self):
        for error in [URLError(TimeoutError()), ConnectionResetError()]:
            with self.subTest(error=type(error).__name__):
                self.opener.open.reset_mock()
                self.opener.open.side_effect = [error, response()]
                generate(self.contents)
                self.assertEqual(self.opener.open.call_count, 2)

    def test_server_failures_allow_one_backup_attempt(self):
        for code in (408, 500, 502, 503, 504):
            with self.subTest(code=code):
                self.opener.open.reset_mock()
                self.opener.open.side_effect = [http_error(code), response()]
                generate(self.contents)
                self.assertEqual(self.opener.open.call_count, 2)

    def test_auth_configuration_and_quota_failures_do_not_switch(self):
        for code in (400, 401, 402, 403, 404, 429):
            with self.subTest(code=code):
                self.opener.open.reset_mock()
                self.opener.open.side_effect = http_error(code, '120s')
                with self.assertRaises(RuntimeError) as failure:
                    generate(self.contents)
                self.assertEqual(self.opener.open.call_count, 1)
                if code == 429:
                    self.assertEqual(failure.exception.retry_after, 121)

    def test_tls_failure_does_not_switch_or_weaken_verification(self):
        for error in [ssl.SSLCertVerificationError('fixture'), URLError(ssl.SSLCertVerificationError('fixture'))]:
            self.opener.open.reset_mock()
            self.opener.open.side_effect = error
            with self.assertRaisesRegex(RuntimeError, 'TLS'):
                generate(self.contents)
            self.assertEqual(self.opener.open.call_count, 1)

    def test_refusal_and_malformed_output_do_not_switch_models(self):
        for fixture in [response(finish='SAFETY'), response(raw=b'not json'), response(raw=b'{"candidates":[]}')]:
            self.opener.open.reset_mock()
            self.opener.open.return_value = fixture
            with self.assertRaises(RuntimeError):
                generate(self.contents)
            self.assertEqual(self.opener.open.call_count, 1)

    def test_safety_refusal_is_not_reported_as_retryable_incomplete_output(self):
        self.opener.open.return_value = response(finish='SAFETY')
        with self.assertRaisesRegex(RuntimeError, 'declined the content'):
            generate(self.contents)
        self.assertEqual(self.opener.open.call_count, 1)

    def test_both_unavailable_returns_safe_error_and_bounded_attempts(self):
        self.opener.open.side_effect = TimeoutError('Sensitive transport detail fixture-primary-key')
        with self.assertRaises(RuntimeError) as failure:
            generate(self.contents)
        self.assertEqual(self.opener.open.call_count, 2)
        self.assertEqual(failure.exception.retry_after, 60)
        self.assertIn('Nothing was approved', str(failure.exception))
        self.assertNotIn('fixture-primary-key', str(failure.exception))

    def test_optional_backup_key_is_used_only_for_backup(self):
        self.config['GEMINI_BACKUP_API_KEY'] = 'fixture-backup-key'
        self.opener.open.side_effect = [TimeoutError(), response()]
        generate(self.contents)
        requests = [call.args[0] for call in self.opener.open.call_args_list]
        self.assertEqual(requests[0].get_header('X-goog-api-key'), 'fixture-primary-key')
        self.assertEqual(requests[1].get_header('X-goog-api-key'), 'fixture-backup-key')

    def test_backup_stays_selected_after_recovery(self):
        self.opener.open.side_effect = [TimeoutError(), response(), response()]
        with api_session():
            generate(self.contents)
            generate(self.contents)
        self.assertIn('gemini-3.5-flash-lite', self.opener.open.call_args.args[0].full_url)
        self.assertEqual(self.opener.open.call_count, 3)

    def test_mid_conversation_handoff_preserves_results_without_foreign_signatures(self):
        first = dict(role='model', parts=[dict(thought=True, text='Private reasoning'),
                     dict(thoughtSignature='PRIMARY_SIGNATURE', functionCall=dict(name='read_file', args=dict(path='virtual.txt'), id='old-call'))])
        second = dict(role='model', parts=[dict(thoughtSignature='BACKUP_SIGNATURE',
                      functionCall=dict(name='open_link', args=dict(url='https://test.example.test'), id='new-call'))])
        self.opener.open.side_effect = [response(first), TimeoutError(), response(second), response()]
        with api_session():
            self.contents.append(generate(self.contents))
            self.contents.append(dict(role='user', parts=[dict(functionResponse=dict(name='read_file', response=dict(content='Previously read data'), id='old-call'))]))
            self.contents.append(generate(self.contents))
            self.contents.append(dict(role='user', parts=[dict(functionResponse=dict(name='open_link', response=dict(content='New page'), id='new-call'))]))
            generate(self.contents)
        migrated = json.loads(self.opener.open.call_args_list[2].args[0].data)
        followup = json.loads(self.opener.open.call_args_list[3].args[0].data)
        self.assertNotIn('PRIMARY_SIGNATURE', json.dumps(migrated))
        self.assertNotIn('Private reasoning', json.dumps(migrated))
        self.assertIn('Previously read data', json.dumps(migrated))
        self.assertEqual(migrated['systemInstruction']['parts'][0]['text'], DEFAULT_SYSTEM)
        self.assertIn('tools', migrated)
        self.assertNotIn('PRIMARY_SIGNATURE', json.dumps(followup))
        self.assertIn('BACKUP_SIGNATURE', json.dumps(followup))
        self.assertIn('New page', json.dumps(followup))
        self.assertEqual(len(followup['contents']), 3)

    def test_new_request_in_session_does_not_inherit_previous_email_history(self):
        self.opener.open.side_effect = [TimeoutError(), response(), response()]
        with api_session():
            generate(self.contents)
            generate([dict(role='user', parts=[dict(text='Independent second email')])])
        sent = json.loads(self.opener.open.call_args.args[0].data)
        self.assertIn('Independent second email', json.dumps(sent))
        self.assertNotIn('fictional note', json.dumps(sent))

    def test_bad_settings_rejected_before_any_network_access(self):
        for name, value in [('GEMINI_TIMEOUT_SECONDS', '0'), ('GEMINI_TIMEOUT_SECONDS', 'NaN'),
                            ('GEMINI_FALLBACK_MODEL', 'https://evil.invalid/key'), ('GEMINI_API_KEY', '')]:
            self.config = dict(CONFIG, **{name: value})
            with self.assertRaises(RuntimeError):
                generate(self.contents)
        self.opener.open.assert_not_called()

    def test_duplicate_model_and_key_are_not_retried_as_a_different_service(self):
        self.config['GEMINI_FALLBACK_MODEL'] = self.config['GEMINI_MODEL']
        self.opener.open.side_effect = TimeoutError()
        with self.assertRaises(RuntimeError):
            generate(self.contents)
        self.assertEqual(self.opener.open.call_count, 1)


if __name__ == '__main__':
    unittest.main()
