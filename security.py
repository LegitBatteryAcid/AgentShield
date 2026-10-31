"""Fail-closed policy gate. No model can grant a URL permission.

This protects tools explicitly routed through Shield; it is not an OS firewall.
"""
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
import ipaddress
import json
import re
import socket
from urllib.parse import unquote, urlsplit, urlunsplit

from config import ROOT


class SecurityViolation(RuntimeError):
    pass


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    url: str = ''
    host: str = ''


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key.lower() in {'href', 'src', 'action', 'formaction', 'data'} and value:
                self.links.append(value)


def extract_links(text):
    """Inspect raw HTML attributes as well as plain/Markdown/encoded URLs."""
    candidates = []
    views = [unescape(text)]
    # Decoding is for detection only. Network requests use the strict original URL.
    for _ in range(2):
        decoded = unquote(views[-1])
        if decoded == views[-1]:
            break
        views.append(decoded)
    for view in views:
        parser = LinkParser()
        parser.feed(view)
        candidates.extend(parser.links)
        candidates.extend(re.findall(r'(?:[a-zA-Z][a-zA-Z0-9+.-]*://|www\.)[^\s<>\"\'`]+', view))
        candidates.extend(re.findall(r'\]\(\s*([^\s)]+)', view))
    return list(dict.fromkeys(x.rstrip('.,;!?)]}') for x in candidates if x and not x.startswith('#')))


INJECTION_PATTERNS = [
    (r'ignore\s+(?:all\s+)?(?:previous|prior|above|system)\s+instructions', 'Instruction override in untrusted content'),
    (r'(?:disable|bypass|turn off)\s+(?:the\s+)?(?:security|shield|safety|guardrail)', 'Attempt to disable security'),
    (r'(?:send|upload|reveal|exfiltrate)\b.{0,70}\b(?:api[ _-]?key|secret|password|credentials)', 'Request to expose credentials'),
    (r'<\|(?:system|assistant|im_start)\|>|\[INST\]', 'Embedded model-role marker'),
]


class Shield:
    def __init__(self, emit=None, policy=None):
        self.policy = policy if policy is not None else json.loads((ROOT / 'policy.json').read_text())
        hosts = self.policy.get('allowed_hosts', [])
        if not isinstance(hosts, list) or not hosts or not all(isinstance(h, str) for h in hosts):
            raise ValueError('policy.json must contain an explicit allowed_hosts list')
        self.allowed_hosts = frozenset(h.lower() for h in hosts)
        self.emit = emit or (lambda event, **data: None)
        self.terminated = False

    def alive(self):
        if self.terminated:
            raise SecurityViolation('Agent run already terminated')

    def block(self, reason, host=''):
        self.terminated = True
        self.emit('blocked', reason=reason, host=host)
        raise SecurityViolation(reason)

    def inspect_url(self, url):
        if not isinstance(url, str) or not url or len(url) > 2048:
            return Decision(False, 'Missing or oversized URL')
        if any(ord(c) < 33 or ord(c) > 126 for c in url) or '\\' in url:
            return Decision(False, 'Ambiguous, Unicode, or control characters in URL')
        try:
            parts = urlsplit(url)
            host = (parts.hostname or '').lower()
            port = parts.port
        except ValueError:
            return Decision(False, 'Malformed URL')
        if parts.scheme.lower() != 'https':
            return Decision(False, 'Only HTTPS URLs are permitted', host=host)
        if parts.username is not None or parts.password is not None:
            return Decision(False, 'URL contains deceptive embedded credentials', host=host)
        if not host or '%' in parts.netloc or host.endswith('.') or any(x.startswith('xn--') for x in host.split('.')):
            return Decision(False, 'Ambiguous or internationalized hostname', host=host)
        if port not in (None, 443):
            return Decision(False, 'Nonstandard network port', host=host)
        try:
            ipaddress.ip_address(host)
            return Decision(False, 'Direct IP addresses are not permitted', host=host)
        except ValueError:
            pass
        if host not in self.allowed_hosts:
            return Decision(False, 'Host is not on the approved list (untrusted, not proven malicious)', host=host)
        # Reject encoded controls/backslashes; path/query never influence the hostname allowlist.
        decoded = unquote(unquote(url))
        if any(ord(c) < 32 or ord(c) == 127 for c in decoded) or '\\' in decoded:
            return Decision(False, 'Encoded control character in URL', host=host)
        normalized = urlunsplit(('https', host, parts.path or '/', parts.query, ''))
        return Decision(True, 'Exact hostname approved', normalized, host)

    def require_url(self, url, stage='tool'):
        self.alive()
        decision = self.inspect_url(url)
        if not decision.allowed:
            self.block(decision.reason, decision.host)
        self.emit('allowed', host=decision.host, stage=stage, reason=decision.reason)
        return decision

    def scan(self, text, stage='source'):
        self.alive()
        if not isinstance(text, str) or len(text) > self.policy['max_input_chars']:
            self.block('Content exceeds the inspection limit')
        self.emit('scan', stage=stage, reason='Inspecting content before agent access')
        for url in extract_links(text):
            # Relative web links are checked when resolved by the fetch tool. Source
            # relative links never grant permission to a network destination.
            if url.startswith(('/', './', '../')) and not url.startswith('//'):
                continue
            self.require_url(url, stage)
        view = unquote(unescape(text))
        for pattern, reason in INJECTION_PATTERNS:
            if re.search(pattern, view, re.I | re.S):
                self.block(reason)
        self.emit('scan_passed', stage=stage, reason='Local policy checks passed')

    def resolve_public(self, host):
        self.alive()
        try:
            answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except OSError:
            self.block('DNS lookup failed; refusing to open URL', host)
        addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
        if not addresses:
            self.block('DNS returned no addresses', host)
        for address in addresses:
            ip = ipaddress.ip_address(address)
            # Reject IPv6 mapped/transition ranges to avoid alternate private routing.
            if not ip.is_global or (ip.version == 6 and (ip.ipv4_mapped or ip.sixtofour or ip.teredo)):
                self.block('DNS points to a private, local, or reserved address', host)
        return addresses[0]
