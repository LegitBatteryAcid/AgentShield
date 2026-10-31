"""The agent's only web capability. All redirects are checked before contact."""
import http.client
from html.parser import HTMLParser
import socket
import ssl
from urllib.parse import urljoin, urlsplit


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, address, timeout):
        super().__init__(host, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        # Connect directly to the vetted address. Keep the original hostname for
        # TLS SNI/certificate verification; no second DNS lookup or proxy routing.
        family = socket.AF_INET6 if ':' in self.address else socket.AF_INET
        raw = socket.socket(family, socket.SOCK_STREAM)
        raw.settimeout(self.timeout)
        try:
            raw.connect((self.address, 443))
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def fetch_url(url, shield):
    for hop in range(shield.policy['max_redirects'] + 1):
        decision = shield.require_url(url, 'redirect' if hop else 'tool')
        address = shield.resolve_public(decision.host)
        parsed = urlsplit(decision.url)
        connection = PinnedHTTPSConnection(decision.host, address, shield.policy['request_timeout_seconds'])
        shield.emit('fetch', host=decision.host, reason='Opening approved URL through guarded tool')
        try:
            target = parsed.path + ('?' + parsed.query if parsed.query else '')
            connection.request('GET', target, headers={
                'User-Agent': 'AgentShield-Hackathon/1.0',
                'Accept': 'text/html,text/plain', 'Accept-Encoding': 'identity'})
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader('Location')
                if not location:
                    shield.block('Redirect has no destination', decision.host)
                # Gate the next destination before any network contact.
                url = urljoin(decision.url, location)
                shield.require_url(url, 'redirect')
                continue
            if response.status != 200:
                raise RuntimeError(f'Approved website returned HTTP {response.status}')
            content_type = response.getheader('Content-Type', '').split(';')[0].lower()
            if content_type not in ('text/html', 'text/plain'):
                shield.block('Unsupported web content type', decision.host)
            if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
                shield.block('Compressed web responses are not supported', decision.host)
            limit = shield.policy['max_response_bytes']
            body = response.read(limit + 1)
            if len(body) > limit:
                shield.block('Web response exceeds the size limit', decision.host)
        finally:
            connection.close()
        text = body.decode('utf-8', errors='replace')
        shield.scan(text, 'fetched page')
        if content_type == 'text/html':
            parser = VisibleText()
            parser.feed(text)
            text = ' '.join(parser.parts)
        return text[:16000]
    shield.block('Too many redirects')
