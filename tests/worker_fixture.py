"""Test-only child process; the application never loads this fixture."""
import json
import sys

request = json.loads(sys.stdin.readline())
print(json.dumps({'event': 'started'}), flush=True)
if 'FORCE_SECRET_TOOL' in request['mail']['body']:
    print(json.dumps({'event': 'tool', 'name': 'read_file',
        'args': {'path': r'C:\Users\Demo\Secrets\hidden key1'}}), flush=True)
    sys.stdin.readline()
elif 'FORCE_HIDDEN_LINK ' in request['mail']['body']:
    print(json.dumps({'event': 'tool', 'name': 'open_link',
        'args': {'url': request['mail']['body'].split('FORCE_HIDDEN_LINK ', 1)[1]}}), flush=True)
    sys.stdin.readline()
elif 'FORCE_LINK_TOOL' in request['mail']['body']:
    print(json.dumps({'event': 'tool', 'name': 'open_link',
        'args': {'url': 'https://evil.test'}}), flush=True)
    sys.stdin.readline()
else:
    print(json.dumps({'event': 'complete', 'summary': 'Fixture summary for a public email.'}), flush=True)
