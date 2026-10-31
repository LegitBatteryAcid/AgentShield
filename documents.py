"""Bounded local text, email and DOCX ingestion. Never execute active content."""
from email import policy
from email.parser import BytesParser
from pathlib import Path
import xml.etree.ElementTree as ET
from zipfile import ZipFile


def read_document(filename):
    path = Path(filename)
    if path.stat().st_size > 2_000_000:
        raise ValueError('Document must be smaller than 2 MB')
    suffix = path.suffix.lower()
    if suffix in {'.txt', '.md', '.html', '.htm'}:
        text = path.read_text(encoding='utf-8-sig')
    elif suffix == '.eml':
        message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
        parts = ['Subject: ' + str(message.get('Subject', ''))]
        for part in message.walk():
            if part.get_content_type() in ('text/plain', 'text/html'):
                parts.append(part.get_content())
            elif not part.is_multipart():
                raise ValueError('Email attachments are not supported; inspect them separately')
        text = '\n'.join(parts)
    elif suffix == '.docx':
        chunks = []
        with ZipFile(path) as archive:
            if sum(info.file_size for info in archive.infolist()) > 4_000_000:
                raise ValueError('Expanded DOCX is too large')
            for info in archive.infolist():
                if info.filename.startswith('word/embeddings/'):
                    raise ValueError('Embedded documents are not supported')
                if info.filename.startswith('word/') and info.filename.endswith('.xml'):
                    root = ET.fromstring(archive.read(info))
                    chunks.extend(node.text for node in root.iter() if node.tag.endswith('}t') and node.text)
                if info.filename.endswith('.rels'):
                    root = ET.fromstring(archive.read(info))
                    chunks.extend(node.get('Target', '') for node in root if node.get('TargetMode') == 'External')
        text = '\n'.join(chunks)
    else:
        raise ValueError('Supported files: TXT, MD, HTML, EML and DOCX. Export PDFs to text for this demo.')
    if len(text) > 60000:
        raise ValueError('Document exceeds the 60,000-character inspection limit')
    return text
