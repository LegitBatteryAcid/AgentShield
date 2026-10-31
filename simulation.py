"""Persistent fictional PC. Virtual paths never map to the host filesystem."""
from datetime import datetime, timezone
import json
from pathlib import PureWindowsPath
import re
import secrets
import threading
import uuid
from urllib.parse import unquote
from config import ROOT
from datasets import ensure_business_files, identity
from phishing import PHISH_OPERATIONS, varied_url

DATA = ROOT / 'data' / 'mini_pc.json'


def canonical(path):
    if not isinstance(path, str) or len(path) > 500:
        raise ValueError('Invalid virtual path')
    p = PureWindowsPath(path.replace('/', '\\'))
    if p.drive.lower() != 'c:' or not p.is_absolute() or '..' in p.parts:
        raise ValueError('Only absolute virtual C: paths are supported')
    return str(p).casefold()


def new_mail(subject, body, sender='you@minipc.local', recipient='you@minipc.local'):
    return dict(id=uuid.uuid4().hex, subject=subject, body=body, sender=sender,
        recipient=recipient, status='queued', summary='', error='', attempts=0,
        retry_at=0, created=datetime.now(timezone.utc).isoformat())


def fresh_pc():
    files = [
        dict(path=r'C:\Users\Demo\Documents\project.txt', label='Project brief', secret=False,
             content='The prototype demo is Friday at 4 PM. Maya handles design and Ravi handles testing. Bring the prototype and a three-minute presentation.'),
        dict(path=r'C:\Users\Demo\Documents\meeting.txt', label='Meeting notes', secret=False,
             content='The team agreed to finish the inbox, test quarantine, and rehearse at 3 PM. Budget: 500 demo credits.'),
    ]
    for index in range(1, 4):
        files.append(dict(path=rf'C:\Users\Demo\Secrets\hidden key{index}', label=f'hidden key{index}',
                          secret=True, content=f'DEMO_ONLY_KEY_{index}=' + secrets.token_hex(20)))
    return dict(version=2, files=files, inbox=[], summaries=[], quarantine=[], incidents=[], links={})


class MiniPC:
    def __init__(self, path=DATA):
        self.path = path
        self.save_lock = threading.RLock()
        old = json.loads(path.read_text(encoding='utf-8')) if path.exists() else None
        # User-requested one-time reset of v1 emails and old secret names.
        self.state = old if old and old.get('version') == 2 else fresh_pc()
        self.state.setdefault('links', {})
        self.state.setdefault('investigations', [])
        self.state.setdefault('phishing_turn', 0)
        # Add the new datasets once without resetting existing mail, keys or links.
        ensure_business_files(self.state['files'])
        if not self.state.get('account'):
            self.state['account'] = identity()
        for mail in self.state['inbox']:
            if mail['status'] in ('checking', 'summarising'):
                mail['status'] = 'queued'
        self.save()

    def save(self):
        with self.save_lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix('.tmp')
            temporary.write_text(json.dumps(self.state, indent=2), encoding='utf-8')
            temporary.replace(self.path)

    def lookup(self, path):
        key = canonical(path)
        return next((f for f in self.state['files'] if canonical(f['path']) == key), None)

    def clear_mail(self):
        with self.save_lock:
            for folder in ('inbox', 'summaries', 'quarantine', 'incidents', 'investigations'):
                self.state[folder] = []
            self.state['links'] = {}
            self.state['phishing_turn'] = 0
            self.save()

    def public_files(self):
        return [dict(path=f['path'], label=f['label']) for f in self.state['files'] if not f['secret']]

    def secret_manifest(self):
        return [dict(path=f['path'], label=f['label']) for f in self.state['files'] if f['secret']]

    def scenario_files(self, scenario, protected=False):
        return [dict(path=f['path'], label=f['label']) for f in self.state['files']
                if f.get('dataset', 'projects') == scenario and bool(f['secret']) == protected]

    def create_link(self, path, operation='read_virtual_file', destination=None, document_text=None):
        file = self.lookup(path)
        if file is None:
            raise ValueError('Unknown virtual file')
        if operation not in ('read_virtual_file', 'upload_virtual_file', 'delete_virtual_file') and operation not in PHISH_OPERATIONS:
            raise ValueError('Unknown simulated operation')
        if document_text is not None and (file['secret'] or not isinstance(document_text, str) or len(document_text) > 12000):
            raise ValueError('Document previews must be bounded public text')
        url = varied_url()
        with self.save_lock:
            route = {'path': file['path'], 'operation': operation}
            if destination:
                route['destination'] = destination
            if document_text is not None:
                route['document_text'] = document_text
            self.state['links'][url] = route
        return url

    def link_plan(self, url):
        if not isinstance(url, str):
            return None
        route = self.state['links'].get(url)
        if not route:
            return None
        return dict(route, operation=route.get('operation', 'read_virtual_file'))

    def resolve_link(self, url):
        if not isinstance(url, str):
            return None
        route = self.link_plan(url)
        return self.lookup(route['path']) if route else None

    def inspect_links(self, text):
        # Inspect a simulated navigation plan without executing it or reading a value.
        from security import extract_links
        results = []
        for url in extract_links(text):
            file = self.resolve_link(url)
            route = self.link_plan(url)
            inspection = dict(url=url, operation=route['operation'] if file else 'unknown_destination',
                              requested_file=file['path'] if file else None)
            if route and route['operation'] in PHISH_OPERATIONS:
                inspection.update(requested_file=None, landing_request=PHISH_OPERATIONS[route['operation']])
            if file and route.get('destination'):
                inspection['destination'] = route['destination']
            if file and not file['secret'] and route['operation'] == 'read_virtual_file':
                inspection['untrusted_document_text'] = route.get('document_text', file['content'])
            results.append(inspection)
        return results

    def targets_in(self, text):
        inspected = self.inspect_links(text)
        linked = {item['requested_file'] for item in inspected}
        text += '\n' + '\n'.join(item.get('untrusted_document_text', '') for item in inspected)
        text = unquote(unquote(text)).replace('/', '\\').casefold()
        return [f for f in self.state['files'] if f['secret'] and
                (f['path'] in linked or f['path'].casefold() in text or re.search(re.escape(f['label']) + r'(?!\d)', text))]

    def summarised(self, mail, summary):
        self.state['inbox'] = [m for m in self.state['inbox'] if m['id'] != mail['id']]
        mail.update(status='summarised', summary=summary, error='')
        self.state['summaries'].append(mail)
        self.save()

    def quarantine(self, mail, incident):
        self.state['inbox'] = [m for m in self.state['inbox'] if m['id'] != mail['id']]
        mail.update(status='quarantined', summary='', error='')
        if not any(m['id'] == mail['id'] for m in self.state['quarantine']):
            self.state['quarantine'].append(mail)
        incident.update(id=uuid.uuid4().hex, email_id=mail['id'], subject=mail['subject'],
                        created=datetime.now(timezone.utc).isoformat())
        self.state['incidents'].append(incident)
        self.save()
