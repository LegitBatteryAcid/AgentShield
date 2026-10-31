# AgentShield

**A Gemini-powered security demo for AI agents reading untrusted emails and documents.**

AgentShield checks emails before an AI summariser acts, blocks unsafe tool requests, and quarantines suspicious messages. Built with Python and Tkinter for a native desktop experience.

## Features

- **Fresh emails:** Gemini generates varied messages with a 70% safe / 30% malicious scenario selection.
- **Automatic protection:** independent Gemini review and Python checks detect phishing and prompt injection.
- **Tool interception:** blocks protected-file access, uploads, deletions and unauthorised messages.
- **Shadow PC:** replays quarantined emails using decoy secrets, records attempted actions, and verifies the three original hidden keys remain intact.
- **Simple interface:** Inbox, Summary and Quarantine, with automatic processing and Gemini timeout failover.

## Setup

Requires **Python 3.11+ with Tkinter**, internet access and a **Gemini API key**. No third-party Python packages are required.

1. Download or clone the repository and open the project folder.
2. Copy `.env.example` to `.env` and enter your Gemini API key. Keep an existing configured `.env`.
3. Start the app:

   ```powershell
   python dashboard.py
   ```

You can also double-click **Start AgentShield.cmd**.

## Try it

Click **Compose** to generate an email. Approved messages move to **Summary**; blocked messages move to **Quarantine**. Select a quarantined message and click **Investigate** to open Shadow PC.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Scope

This is a **simulation**, not a Windows VM or system-wide antivirus. Gemini runs through Google's API. Emails, files and attack destinations are virtual; replay transfers are captured locally. Detection can produce false positives and false negatives.

**Never upload `.env` or real secrets.** The included `.gitignore` excludes API settings, local mailbox data and virtual environments.

Google Sans is bundled under the [SIL Open Font License](assets/fonts/OFL.txt).
