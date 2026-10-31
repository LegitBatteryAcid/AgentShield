"""Explicit test-only worker. Never used by the application."""
import json
import sys
import time

request = json.loads(sys.stdin.readline())
body = request['mail']['body']
if body == 'WAIT':
    print(json.dumps(dict(event='started')), flush=True)
    time.sleep(30)
elif body == 'ERROR':
    print(json.dumps(dict(event='error', message='Fixture API failure')), flush=True)
else:
    commands = json.loads(body)
    contents = []
    for command in commands:
        print(json.dumps(dict(event='tool', **command)), flush=True)
        response = json.loads(sys.stdin.readline())
        contents.append(response['result'].get('content', ''))
    print(json.dumps(dict(event='complete', summary='Fixture response. ' + '\n'.join(contents))), flush=True)
