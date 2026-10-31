"""Read local settings without evaluating .env or exposing credentials."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def settings():
    values = {}
    path = ROOT / '.env'
    if path.exists():
        for line in path.read_text(encoding='utf-8-sig').splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            name, value = line.split('=', 1)
            values[name.strip()] = value.strip().strip('\"\'')
    return {name: os.environ.get(name, values.get(name, default)) for name, default in (
        ('GEMINI_API_KEY', ''), ('GEMINI_MODEL', 'gemini-3.1-flash-lite'),
        ('GEMINI_FALLBACK_MODEL', 'gemini-3.5-flash-lite'), ('GEMINI_BACKUP_API_KEY', ''),
        ('GEMINI_TIMEOUT_SECONDS', '25'))}
