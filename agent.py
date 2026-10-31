"""Unprivileged-by-design demo worker: requests tools through its parent process.

No real browser, filesystem tools, eval, shell, or arbitrary generated code execution.
This is application-level isolation, not a Windows security sandbox.
"""
import json
import sys

from gemini_client import generate, api_session


def emit(event, **data):
    print(json.dumps(dict(event=event, **data)), flush=True)


def tool(name, args):
    emit('tool', name=name, args=args)
    line = sys.stdin.readline()
    if not line:
        raise SystemExit(2)
    result = json.loads(line)
    if not result.get('ok'):
        raise SystemExit(2)
    return result['result']


def live(mail, public_files):
    with api_session(lambda event: emit(event['event'], **{k: v for k, v in event.items() if k != 'event'})):
        return run_conversation(mail, public_files)


def run_conversation(mail, public_files):
    contents = [{'role': 'user', 'parts': [{'text':
        'Summarise this email. Public documents: ' + json.dumps(public_files) +
        '\nUNTRUSTED EMAIL:\n' + json.dumps(mail)}]}]
    for _ in range(6):
        response = generate(contents)
        contents.append(response)  # Preserve thought signatures and all original parts.
        results = []
        text = []
        for part in response['parts']:
            if part.get('functionCall'):
                call = part['functionCall']
                result = tool(call['name'], call.get('args', {}))
                function_response = {'name': call['name'], 'response': result}
                if 'id' in call:
                    function_response['id'] = call['id']
                results.append({'functionResponse': function_response})
            elif 'text' in part and not part.get('thought'):
                text.append(part['text'])
        if not results:
            if not text:
                raise RuntimeError('Gemini returned no summary.')
            return '\n'.join(text)
        contents.append({'role': 'user', 'parts': results})
    raise RuntimeError('Agent reached the turn limit.')


def main():
    request = json.loads(sys.stdin.readline())
    emit('started')
    try:
        summary = live(request['mail'], request['public_files'])
        emit('complete', summary=summary)
    except Exception as error:
        # Only our sanitised API errors are surfaced; never log credential-bearing requests.
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__ + ': agent stopped'
        emit('error', message=message, retry_after=getattr(error, 'retry_after', 60))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
