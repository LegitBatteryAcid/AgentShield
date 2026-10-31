"""Restricted Markdown link parsing for the native email reader."""
import re

LINK = re.compile(r'\[([^\]\r\n]{1,160})\]\((https://[^\s()<>]+)\)')


def parse_links(text):
    return [dict(label=m.group(1), url=m.group(2), start=m.start(), end=m.end())
            for m in LINK.finditer(text)]
