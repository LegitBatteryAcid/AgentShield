"""Trusted parent: secrets stay here, outside the agent worker's IPC input."""
from security import Shield, SecurityViolation
from phishing import analyse_email, PHISH_OPERATIONS


class Broker:
    def __init__(self, pc, mail, emit=None):
        self.pc, self.mail = pc, mail
        self.emit = emit or (lambda event, **data: None)
        self.shield = Shield(self.emit)
        self.calls = 0
        self.incident = None

    def deny(self, reason, tool, target='', file=None, evidence='requested operation', category='blocked_action'):
        targets = self.pc.targets_in(self.mail['subject'] + ' ' + self.mail['body'] + ' ' + target)
        if file and not any(item['path'] == file['path'] for item in targets):
            targets.append(file)
        self.incident = dict(reason=reason, tool=tool, target=target, evidence=evidence,
            category=category, affected_files=[dict(path=f['path'], label=f['label']) for f in targets],
            secrets=[dict(path=f['path'], label=f['label'], preview=f['content']) for f in targets if f['secret']],
            secret_bytes_delivered=0, process_terminated=False)
        route = self.pc.link_plan(target)
        if route and route.get('destination'):
            self.incident['destination'] = route['destination']
        self.shield.block(reason)

    def inspect_email(self):
        analysis = analyse_email(self.mail)
        if analysis['block']:
            signals = [s for s in analysis['signals'] if s['severity'] == 'high']
            try:
                self.deny('Phishing language: ' + '; '.join(dict.fromkeys(s['reason'] for s in signals)),
                          'email_text_check', evidence='High-risk requests found in the email before agent access.',
                          category='phishing_language')
            finally:
                if self.incident:
                    self.incident['text_signals'] = analysis['signals']

    def reject_review(self, reason):
        source = self.mail['subject'] + '\n' + self.mail['body']
        inspections = self.pc.inspect_links(source)
        secrets = self.pc.targets_in(source)
        file = secrets[0] if secrets else None
        target = file['path'] if file else ''
        category = 'security_review'
        analysis = analyse_email(self.mail)
        for inspection in inspections:
            requested = inspection.get('requested_file')
            candidate = self.pc.lookup(requested) if requested else None
            operation = inspection['operation']
            if operation in PHISH_OPERATIONS:
                file, target, category = None, inspection['url'], 'phishing_link'
                break
            if operation in ('upload_virtual_file', 'delete_virtual_file'):
                file, target = candidate, inspection['url']
                category = 'data_upload' if operation == 'upload_virtual_file' else 'file_deletion'
                break
            if candidate and candidate['secret']:
                file, target = candidate, inspection['url']
                category = 'protected_data_access' if candidate.get('dataset') else 'hidden_key_access'
                break
            if inspection.get('untrusted_document_text') and secrets:
                target, category = inspection['url'], 'document_injection'
                break
        if category == 'security_review' and analysis['signals']:
            category = 'phishing_language'
        try:
            self.deny(reason, 'security_review', target, file,
                evidence='Security Gemini inspected email wording, requested operations and document content before summarisation. No requested action was executed.',
                category=category)
        finally:
            if self.incident:
                self.incident['text_signals'] = analysis['signals']

    def inspect_content(self, content, name, target, file):
        analysis = analyse_email(dict(body=content))
        if analysis['block']:
            try:
                self.deny('High-risk phishing request inside the linked document.', name, target, file,
                          evidence='Document wording blocked before it reached the summariser.', category='phishing_language')
            finally:
                if self.incident:
                    self.incident['text_signals'] = analysis['signals']
        try:
            self.shield.scan(content, 'document content')
        except SecurityViolation as error:
            self.deny(str(error), name, target, file,
                evidence='Instructions embedded in document content were intercepted before reaching the summariser.',
                category='document_injection')

    def dispatch(self, name, args):
        self.shield.alive()
        self.inspect_email()
        self.calls += 1
        if self.calls > 8:
            self.deny('Agent exceeded the tool-call budget', name)
        if not isinstance(args, dict):
            self.deny('Invalid tool arguments', name)
        self.emit('tool_request', tool=name, target=str(args.get('path', args.get('url', args.get('recipient', ''))))[:500])
        if name == 'read_file':
            path = args.get('path', '')
            try:
                file = self.pc.lookup(path)
            except (ValueError, TypeError):
                self.deny('Attempted access outside the virtual filesystem', name, str(path))
            if file is None:
                self.deny('Unknown virtual file; no host filesystem access permitted', name, str(path))
            if file['secret']:
                self.deny('Protected file read intercepted before data was returned', name, path, file,
                          category='protected_data_access' if file.get('dataset') else 'hidden_key_access')
            self.inspect_content(file['content'], name, path, file)
            self.emit('allowed', reason='Public virtual document read permitted', target=file['path'])
            return {'content': file['content']}
        if name == 'open_link':
            url = args.get('url', '')
            file = self.pc.resolve_link(url)
            if file is not None:
                plan = self.pc.link_plan(url)
                if plan['operation'] in PHISH_OPERATIONS:
                    self.deny(PHISH_OPERATIONS[plan['operation']], name, url,
                              evidence='Simulated phishing landing page blocked. No credentials, consent or payment supplied.',
                              category='phishing_link')
                if plan['operation'] == 'upload_virtual_file':
                    self.deny('This link attempted to upload a file to an external destination.', name, url, file,
                        evidence='Outbound transfer blocked. No file contents were read or transmitted.', category='data_upload')
                if plan['operation'] == 'delete_virtual_file':
                    self.deny('This link attempted to delete a file.', name, url, file,
                        evidence='Deletion blocked. The original file is unchanged.', category='file_deletion')
                if plan['operation'] != 'read_virtual_file':
                    self.deny('Unsupported link operation.', name, url, file)
                if file['secret']:
                    self.deny('The link attempted to open a protected file: ' + file['label'] + '.', name, url, file,
                        evidence='Simulated hyperlink resolved to a protected file. Read blocked before returning its contents.',
                        category='protected_data_access' if file.get('dataset') else 'hidden_key_access')
                content = plan.get('document_text', file['content'])
                self.inspect_content(content, name, url, file)
                self.emit('allowed', reason='Linked public document opened', target=file['path'])
                return {'title': file['label'], 'content': content}
            decision = self.shield.inspect_url(url)
            if not decision.allowed:
                self.deny(decision.reason, name, str(url), evidence='URL requested; listed secret is referenced by the email/URL, not read')
            # Mini-PC browser is intentionally simulated; no live phishing page is fetched.
            self.emit('allowed', reason='Approved URL opened in simulated browser', host=decision.host)
            return {'content': 'Simulated browser page for ' + decision.host + '. No real network request was made.'}
        if name == 'send_email':
            self.deny('The summarising agent has no permission to send messages', name, str(args.get('recipient', '')),
                category='unauthorised_message')
        if name in ('upload_file', 'delete_file'):
            path = args.get('path', '')
            try:
                file = self.pc.lookup(path)
            except (TypeError, ValueError):
                file = None
            upload = name == 'upload_file'
            self.deny('The summarising agent has no permission to ' + ('upload' if upload else 'delete') + ' files.',
                name, str(path), file, evidence='Operation blocked before any file read, transmission or modification.',
                category='data_upload' if upload else 'file_deletion')
        self.deny('Unknown tool denied by default', str(name))

