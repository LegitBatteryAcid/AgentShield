"""Explicit opt-in connection test; importing this module makes no API call."""
from gemini_client import generate, api_session


def main():
    try:
        with api_session(lambda event: print(event['message'])):
            response = generate([{'role': 'user', 'parts': [{'text': 'Reply with exactly: AgentShield connection OK'}]}], use_tools=False)
        print('\n'.join(p['text'] for p in response['parts'] if 'text' in p and not p.get('thought')))
        return 0
    except Exception as error:
        print(str(error) if isinstance(error, RuntimeError) else type(error).__name__ + ': connection failed')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
