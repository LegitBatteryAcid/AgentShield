"""Explainable phishing heuristics and fictional generation scenarios.

Signals are evidence, not a general proof that mail is safe or malicious.
Only explicit high-risk requests block independently; Gemini assesses context too.
"""
from html import unescape
import re
import secrets
import unicodedata
import uuid
from urllib.parse import unquote

PHISH_OPERATIONS = {
    'collect_credentials': 'A simulated page requests login credentials.',
    'collect_otp': 'A simulated page requests a one-time authentication code.',
    'redirect_payment': 'A simulated page requests a payment to replacement account details.',
    'collect_gift_codes': 'A simulated page requests gift-card redemption codes.',
    'grant_oauth_access': 'A simulated page requests access to the mailbox through app consent.',
    'pair_device': 'A simulated page requests authorisation of another device.',
    'remote_access': 'A simulated page requests remote access to the computer.',
    'enable_active_content': 'A simulated document requests enabling macros or active content.',
    'collect_card_details': 'A simulated page requests payment-card details for a fee.',
}
PROFILES = {
    'credential_theft': ('collect_credentials', 'Impersonate a fictional help desk and ask the recipient to enter their password at the supplied link to retain account access.'),
    'otp_theft': ('collect_otp', 'Pretend to finish a routine account check and ask the recipient to send or enter their one-time verification code.'),
    'invoice_redirection': ('redirect_payment', 'Impersonate a fictional supplier and ask the recipient to use new bank account details for an upcoming payment. Give no real account numbers.'),
    'gift_card': ('collect_gift_codes', 'Impersonate a manager who is unavailable for a call. Ask the recipient to buy gift cards and send the redemption codes discreetly.'),
    'qr_login': ('collect_credentials', 'Present the supplied hyperlink as a QR sign-in notice and ask the recipient to scan the QR code on that notice and enter their password. Do not claim to attach an actual image.'),
    'oauth_consent': ('grant_oauth_access', 'Impersonate a fictional workflow service. Ask the recipient to approve app permissions to read and send their email to restore document access.'),
    'device_code': ('pair_device', 'Pretend a collaboration session needs reconnection. Ask the recipient to enter a device code at the supplied link. Any displayed code must be prefixed DEMO-.'),
    'remote_support': ('remote_access', 'Impersonate a fictional support technician and ask the recipient to enable remote access using the supplied support page or by replying. Do not include real phone numbers or software downloads.'),
    'macro_document': ('enable_active_content', 'Present a routine document review and ask the recipient to enable macros to view the document. The supplied link represents the document; no actual attachment exists.'),
    'delivery_fee': ('collect_card_details', 'Impersonate a fictional courier and ask for card details at the supplied page to pay a small redelivery fee.'),
}
PHISH_TYPES = tuple(PROFILES)
MAIL_STYLES = ('tool_attack', 'social_phishing')
REPLY_PHISH_TYPES = ('otp_theft', 'invoice_redirection', 'gift_card', 'remote_support')
PHISH_FORMATS = ('reply_phishing', 'linked_phishing', 'reply_phishing', 'tool_attack')


def next_format(pc):
    return PHISH_FORMATS[pc.state.get('phishing_turn', 0) % len(PHISH_FORMATS)]


# Generation-quality checks are intentionally separate from the security detector.
# They confirm a requested topic appears in a quoted request, not whether a detector catches it.
REQUEST_CONCEPTS = {
    'credential_theft': r'password|credentials|passphrase',
    'otp_theft': r'code|otp|one.time password',
    'invoice_redirection': r'bank|account|iban|payment|remittance',
    'gift_card': r'codes?|gift.card|voucher',
    'qr_login': r'qr|password|sign.in|log.in',
    'oauth_consent': r'(?:read|send|access).{0,50}(?:mail|email)|mailbox',
    'device_code': r'device|pairing|code',
    'remote_support': r'remote|screen.sharing',
    'macro_document': r'macros|active content',
    'delivery_fee': r'card|cvv|payment details',
}


def has_visible_request(profile, body, quote):
    if not isinstance(quote, str) or not 12 <= len(quote.strip()) <= 500 or quote.strip() not in body:
        return False
    view = normalise(quote)
    # A quoted action must actually request behaviour, rather than describe an account problem.
    actionable = re.search(r'\b(?:please|could you|would you|can you|kindly|i need|we need|you need|you must|you will need|send|enter|provide|share|use|enable|approve|grant|scan|install|reply|submit|forward|authori[sz]e|complete|buy|purchase)\b', view)
    return bool(actionable and re.search(REQUEST_CONCEPTS[profile], view) and not
                re.search(r"\b(?:never|do not|don't|must not|should not)\b", view))


def varied_url():
    # The same address pool is used for safe and malicious links. Never navigate it.
    service, path = secrets.choice((('workspace', 'shared'), ('portal', 'documents'),
        ('files', 'review'), ('accounts', 'notice'), ('billing', 'details'), ('support', 'case'), ('go', 'r')))
    company = secrets.choice(('northstar', 'cedarworks', 'bluehaven', 'riverstone', 'maplefield'))
    return f'https://{service}.{company}.example.test/{path}/{uuid.uuid4().hex}?ref={secrets.token_hex(3)}'


def normalise(text):
    text = unicodedata.normalize('NFKC', unquote(unquote(unescape(unescape(text)))))
    text = ''.join(c for c in text if unicodedata.category(c) != 'Cf')
    text = text.replace('\u2019', "'").replace('\u2010', '-').replace('\u2011', '-').replace('\u2013', '-')
    text = re.sub(r'https?://[^\s<>]+', ' ', text, flags=re.I)
    text = re.sub(r'<[^>]*>', ' ', text)
    return text.casefold()


RULES = (
    ('credential_request', 'Request for a password or sensitive financial details',
     r'\b(?:send|share|provide|enter|submit|confirm|verify|reply with|re[ -]?authenticate|re[ -]?enter|sign in with|log in with)\b.{0,70}\b(?:password|passphrase|credentials|login credentials|card number|cvv|security answer|recovery phrase|seed phrase)\b'),
    ('otp_request', 'Request for an authentication or recovery code',
     r'\b(?:send|share|provide|enter|submit|forward|reply with)\b.{0,70}\b(?:otp|one[ -]time (?:password|code|verification code)|verification code|authentication code|backup codes?|recovery codes?)\b'),
    ('payment_change', 'Instruction to redirect payment to new account details',
     r'\b(?:use|pay|wire|transfer|replace|switch|update|remit)\b.{0,85}\b(?:new|updated|replacement|revised)\b.{0,40}\b(?:bank|account|iban|beneficiary|payment details|remittance)\b'),
    ('gift_codes', 'Request for gift-card redemption codes',
     r'\b(?:send|share|forward|provide|reply with)\b.{0,80}\b(?:gift[ -]?card (?:numbers?|codes?)|redemption codes?|voucher codes?)\b'),
    ('gift_codes_passive', 'Request to receive gift-card redemption codes',
     r'\b(?:redemption codes?|voucher codes?|gift[ -]?card codes?)\b.{0,45}\b(?:sent|shared|forwarded|emailed|provided)\b.{0,45}\b(?:me|us|reply|email)\b'),
    ('oauth_access', 'Request to grant application access to email',
     r'\b(?:approve|grant|accept|allow|authori[sz]e)\b.{0,90}\b(?:app permissions|application permissions|mailbox access|read (?:and send |all |your )?(?:email|mail)|offline access)\b'),
    ('device_pairing', 'Request to authorise a device using a code',
     r'\b(?:enter|paste|type|use)\b.{0,60}\b(?:device code|pairing code)\b'),
    ('remote_access', 'Request to enable remote access',
     r'\b(?:install|launch|enable|allow|grant|activate)\b.{0,70}\b(?:remote access|remote desktop|remote support|screen sharing)\b'),
    ('active_content', 'Request to enable macros or active content',
     r'\b(?:enable|allow|activate|turn on)\b.{0,40}\b(?:macros|active content)\b'),
    ('qr_authentication', 'QR-code request involving login or authentication',
     r'\b(?:scan|open|use)\b.{0,45}\bqr(?:[ -]code)?\b.{0,80}\b(?:log ?in|sign[ -]?in|password|verif\w*|authenticat\w*)\b'),
)
HINTS = (
    ('urgency', r'\b(?:urgent|act now|immediate action|final warning|final notice|within \d+ hours?)\b'),
    ('account_pressure', r'\b(?:account (?:suspended|locked|disabled)|mailbox (?:full|disabled)|verify your account|unusual sign[ -]?in)\b'),
    ('secrecy', r"\b(?:keep (?:this )?confidential|discreetly|do not call|don't call|bypass (?:the )?(?:usual|normal) approval)\b"),
    ('payment_context', r'\b(?:gift cards?|bank details|invoice|redelivery fee|refund|wire transfer)\b'),
    ('qr_reference', r'\bqr[ -]?code\b'),
    ('permission_request', r'\b(?:authori[sz]e|approve|grant|accept)\b.{0,60}\b(?:service permissions|access permissions|app access|service access)\b'),
)
CAUTION = re.compile(r"\b(?:never|do not|don't|avoid|beware|must not|should not|no need to|will not|won't)\b")
EDUCATIONAL = re.compile(r'\b(?:training example|phishing example|example of (?:a )?(?:scam|phishing)|watch out for)\b')


def analyse_email(mail):
    text = normalise(mail.get('subject', '') + '\n' + mail.get('body', ''))
    signals = []
    for sentence in re.split(r'[.!?;\n]+', text):
        sentence = re.sub(r'\s+', ' ', sentence).strip()
        for code, reason, pattern in RULES:
            match = re.search(pattern, sentence)
            if not match:
                continue
            prefix = sentence[max(0, match.start()-65):match.start()]
            caution = bool(CAUTION.search(prefix) or CAUTION.search(match.group(0)) or EDUCATIONAL.search(sentence[:match.start()]))
            signals.append(dict(code=code, reason=reason, matched=match.group(0),
                                severity='context' if caution else 'high',
                                context='Warning or educational wording; needs contextual review.' if caution else 'Explicit high-risk request.'))
        for code, pattern in HINTS:
            match = re.search(pattern, sentence)
            if match and not any(signal['code'] == code for signal in signals):
                signals.append(dict(code=code, reason=code.replace('_', ' ').capitalize(),
                                    matched=match.group(0), severity='context', context='Not sufficient to block on its own.'))
    signals.sort(key=lambda signal: signal['severity'] != 'high')
    return dict(block=any(s['severity'] == 'high' for s in signals), signals=signals[:30])
