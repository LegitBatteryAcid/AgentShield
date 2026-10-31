# AgentShield — automatic Gemini mini PC

Native Python desktop simulation with a generated inbox, independent Gemini security reviewer, Gemini summariser, fictional hidden keys, customer records, payroll data and quarantine. **Internet and a working Gemini API key are required. There is no offline mode.**

The native interface uses a Gmail-inspired layout with neutral backgrounds, a white reading pane, red quarantine accents and soft-yellow controls and selections. Mail and Shadow PC tables have horizontal row dividers, darker headings and a red selection marker. Compose and the three folders sit in the left sidebar. Google Sans Regular and Bold are bundled under the SIL Open Font License and loaded privately on Windows; no system font installation is needed. Files and Business data remain hidden, and Shadow PC's integrity display shows only the three hidden keys. Helper captions and the bottom status bar are removed; active progress and errors appear in the header. See [Google's Gmail design overview](https://blog.google/products-and-platforms/products/gmail/gmail-design-update/) and the bundled font license in `assets/fonts/OFL.txt`.

## Start

Double-click **Start AgentShield.cmd**, run `python dashboard.py`, or use the supplied VS Code debug configuration. Python 3.11+ with Tkinter is required; the standard Windows installer includes it. No pip dependencies are needed.

The existing `.env` is preserved. For another machine, copy `.env.example` to `.env` and enter:

```dotenv
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-3.1-flash-lite
GEMINI_FALLBACK_MODEL=gemini-3.5-flash-lite
GEMINI_TIMEOUT_SECONDS=25
# Optional: otherwise the backup uses GEMINI_API_KEY.
GEMINI_BACKUP_API_KEY=
```

`python test_gemini.py` makes a small connection test. Change the model setting if your Google account uses another available model.

## Automatic Gemini failover

On a network timeout, interrupted connection, HTTP 408, or HTTP 500/502/503/504, the current request makes **one backup attempt** after a short jittered delay. Defaults are **Gemini 3.1 Flash-Lite → Gemini 3.5 Flash-Lite**, with a 25-second socket timeout per attempt. Socket timeouts apply to network operations, not a strict overall wall-clock deadline. The existing agent/replay supervisor still imposes its 160-second overall limit.

This applies to the writer, security reviewer, summariser and Shadow PC worker. The existing key is used for both models unless `GEMINI_BACKUP_API_KEY` is set locally. No second key is required. These defaults also apply to existing installations whose `.env` has no backup settings; updating does not overwrite your key. Use an empty `GEMINI_FALLBACK_MODEL` to disable the backup, or configure another text model that supports structured output and function calling. Timeout values must be whole seconds from 5 to 60. Each attempted request may incur the provider's usual usage charges.

The header reports a switch and successful reconnection. After recovery, a conversation keeps using the working model. If switching during a tool conversation, the backup receives a fresh conversation containing the original task and a text record of completed tool results. Foreign thought signatures are excluded; subsequent turns preserve the backup's own signatures. The client does not execute old tool requests again. Any new tool request from either model still goes through the same broker and limits. No file permissions or security checks are relaxed.

Failover is for transport/service availability, **not** for overriding safety refusals, malformed output, invalid credentials, invalid model configuration, TLS verification failures or quota exhaustion. HTTP 429 continues to use the existing queued retry/backoff behaviour. A failed or invalid security review never releases the email to the summariser. If all transport attempts fail, existing mail remains pending for a later retry; Compose reports failure without adding a substitute email, and Shadow PC retains its partial evidence as an incomplete run. Both models use Google's service, so a shared network/provider outage may affect both.

Reference: [Google's Gemini retry guidance](https://ai.google.dev/gemini-api/docs/troubleshooting).

## Use the demo

Click **Compose**. Gemini writes a fresh natural-looking email, delivers it to the simulated Inbox, and processing starts automatically. There is no Run button or scenario selector.

**Clear** empties Inbox, Summary and Quarantine together, including incident history, Shadow PC replays and simulated links. Hidden-key files, business data and Gemini settings are preserved. It works while an email or investigation is running: active agent/replay workers are stopped, new work is paused, and the button shows **Clearing…** until pending work finishes. An already-running Gemini writing or security request may need to return or time out first. Its late result is discarded, then all folders are cleared together so deleted mail cannot reappear.

Each click independently selects a malicious generation scenario with probability 30%, otherwise a safe scenario with probability 70%. This is a per-email probability, not a guarantee of exactly three malicious emails in ten. Generation retries preserve the original selection. Failed generation does not deliver a substitute/template email.

Safe emails contain one ordinary-looking shared-document hyperlink. The malicious/safe choice remains an independent 30%/70% draw. Successfully generated malicious emails rotate through **reply-only phishing → linked phishing → reply-only phishing → hidden tool attack**, then repeat. Thus two of each four malicious examples have no links, one has an explicit phishing request plus a link, and one retains the subtle hidden-tool behaviour. This rotation only controls format after a malicious draw; it does not force every fourth email to be malicious. It starts with reply-only phishing, survives restarting, and resets with Clear. A failed generation does not advance it.

Reply-only phishing randomly selects OTP theft, supplier payment redirection, gift-card requests or remote-support requests. Linked phishing randomly selects one of all ten social-phishing styles. Hidden tool attacks select one of the four operations below equally. For hidden tool attacks, the writer gets the same neutral prompt as safe emails, with no hidden-key name, target path or malicious label. For social phishing, it gets a fictional scenario goal and varied tone. Those generation labels/goals are never passed to the security reviewer or summariser. Whenever a scenario targets a hidden key, each of the three keys has an independent one-in-three chance.

The interface renders each link's readable label, such as “updated notes”, rather than its URL. Links vary across workspace, portal, files, accounts, billing, support and short-link-style paths on fictional company `.example.test` domains. Each link has fresh random tokens; the same address pool serves safe and malicious mail. Python supplies the registered URL and Gemini writes the surrounding email and link label. No external page is fetched. Exact repeats of recent subjects or bodies are retried once; no fixed email template is substituted on failure.

Each Compose also independently chooses **project coordination, customer operations or payroll coordination** with equal probability. Both safe and malicious messages use these topics; mentioning payroll or customers is not itself suspicious. Gemini writes a fresh subject and body using the chosen topic. Sender names, addresses and fictional company domains are generated locally for each email, with a random address suffix. The address is authoritative even if Gemini returns an extra sender field. All generated addresses use reserved `.example.test` domains. Your simulated mailbox is assigned its own random name/address once and retains it across launches and Clear; all new emails arrive at that address. Existing messages retain their original addresses.

## Business datasets

The simulation includes two locally generated, fictional CSV datasets. The **Files** and **Business data** sidebar buttons are hidden; **Hidden keys** remains available:

| Dataset | Contents | Safe document used by normal emails |
|---|---|---|
| Customer records | 12 fictional customers: names, email addresses, companies, plans, demo contract values and private CRM tokens | Customer handover notes with a support/onboarding schedule |
| Employee payroll | 8 fictional employees: names, email addresses, departments, demo salaries, fake bank and tax references | Payroll calendar with timesheet deadlines |

These are synthetic business scenarios, not downloaded breach records or benchmark corpora. Bank/tax references are visibly prefixed `DEMO-`; no real account details are used. The public briefs contain no individual records. Both CSV files are protected by the same broker as the hidden keys. The writer receives a neutral topic and names, never the private records. Security receives protected-file metadata and requested operations, never protected contents.

Malicious customer/payroll links can request a confidential CSV read, upload, deletion, or open a public brief containing instructions to extract the CSV. Safe links open only the corresponding public brief. Quarantine Details identifies the actual dataset targeted. The existing project scenarios and equal selection among hidden key1/2/3 remain available.

The datasets and mailbox identity are added automatically on the next launch, without clearing existing messages, keys, links or replay history. They persist locally and survive Clear.

| Scenario | Hidden link behaviour | Protection |
|---|---|---|
| Protected file access | Opens a hidden key, customer CSV or payroll CSV, according to the selected topic | Confidential file read denied |
| Data upload | Requests transfer of the selected confidential file to a fictional external endpoint | Outbound transfer denied before reading or sending data |
| File deletion | Requests deletion of a public project document or the selected confidential business CSV | Delete operation denied; original file retained |
| Document injection | Opens a public-looking document containing instructions to read the confidential file and put it in the summary | Gemini reviews nested document instructions; Python also scans content and enforces file permissions |

The email text is freshly written by Gemini. The attack operations and embedded instruction examples are controlled simulation fixtures, not model-generated executable code. No real uploads, deletions or email sends occur.

## Phishing language and varied lures

The ten social-phishing styles are credential theft, OTP theft, supplier payment redirection, executive gift-card impersonation, QR login notices, OAuth consent, device-code pairing, remote support, macro-enabled document lures and delivery-fee/card-detail requests. OTP, payment-redirection, gift-card and remote-support styles are used in the reply-only slots. Sender identities remain randomly generated per message. These are synthetic scenarios, not a downloaded corpus or a claim to cover every phishing technique.

Social-phishing generation must include a concrete risky request in the email body. Gemini also returns a private generation-only quote of that sentence; validation checks that it actually occurs in the body, asks for action and mentions the selected scenario's subject. Vague “review this portal” responses are retried with the same scenario. No fixed phishing sentence is injected as a fallback. These generation-quality checks are separate from detection and are not an independent phishing benchmark. The quote is not included in the delivered email metadata or supplied to the security reviewer.

Every email is checked automatically by the independent Gemini reviewer and a local phrase analyser before the summariser receives it. Gemini receives the original wording, local text signals and actual registered link operations. A valid safe Gemini verdict does not override a high-risk local request or the tool broker. Quarantine **Details** includes the matching wording (normalised for detection) and its reason.

The local rules recognise explicit requests for passwords, authentication codes, seed phrases, gift-card codes, replacement payment accounts, app consent, device pairing, remote access and macros. They also collect weaker signals such as urgency, account pressure, secrecy, invoice/refund references and QR mentions. Those weaker keywords alone do not trigger a block. Negated warnings and common educational framing are passed to Gemini for contextual assessment. HTML entities, URL-encoded text, full-width characters and zero-width characters are normalised for phrase matching.

These heuristics can miss paraphrases or flag legitimate requests; they are not a complete phishing classifier. Gemini provides contextual review and can also make mistakes. Local tool restrictions remain in effect. The test suite includes warnings such as “never send your password”, normal urgent invoice meetings, encoded wording, passive gift-code requests and deliberately mistaken safe model verdicts.

QR support currently means detecting **QR-themed email wording**, not decoding QR images. Macro and remote-support scenarios do not create attachments or install software. OAuth/device-code pages are local simulated landing requests, with no real authorisation flow. In Shadow PC, a visit to such a page is recorded as a visit, never as proof that credentials were stolen or consent was granted.

Background references: [FTC phishing guidance](https://consumer.ftc.gov/articles/how-recognize-avoid-phishing-scams), [Microsoft consent-phishing guidance](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/protect-against-consent-phishing), and [Microsoft identity-attack techniques](https://www.microsoft.com/en-us/security/blog/2025/05/29/defending-against-evolving-identity-attack-techniques/).

* **Inbox:** emails waiting, being checked or being summarised.
* **Summary:** approved emails and their automatically generated summaries. **View original** opens the original message in the same reader.
* **Quarantine:** rejected emails, removed from Inbox but retained for inspection. **Details** shows the attack category, reason, affected file, upload destination when relevant, and fictional secret value when a hidden key was targeted. **Investigate** replays the task in a disposable Shadow PC.

The interface has one mail reader, no split summary/security panel, and no live activity log. Hyperlinks are clickable: safe destinations open the corresponding virtual document; protected-file access, upload, deletion and detected document-injection attempts are stopped by the same broker used for agent tools. Clicking never launches a real browser or reads a host file.

Hidden-key values are randomly generated when the mini PC is created, persist locally, and appear only in the trusted observer UI. Filenames and paths may be included in Gemini requests; **key contents are never supplied by the application to any of the three Gemini roles**. A quarantined email stopped at security review never reaches the summariser, so its report says the file was targeted, not actually read.

## Shadow PC: investigate an attack

Select a quarantined email and click **Investigate**. The first replay starts automatically. Reopening it shows its saved result; **Replay again** starts a fresh Gemini conversation with fresh decoys. The original email stays in Quarantine.

The investigation copies the virtual files and link registry into memory and replaces all three hidden-key values with unique `SHADOW_DECOY_...` tokens. Copies of those original values in email/document text are also replaced. No original key value is passed to this worker. The worker uses the **same Gemini model, summariser instructions and tool declarations** as the normal summariser. It receives no scenario label, no security verdict and no instruction to perform an attack. The security reviewer is not rerun: only this disposable copy uses a different tool broker that permits simulated reads, uploads, sends and deletions.

Customer and payroll CSVs also get disposable copies. Every record value is replaced while preserving field names and record count, and a unique trace-token column is added. A simulated upload therefore displays a recognisable table of decoys, not the original records. The visible integrity comparison shows only hidden key1, hidden key2 and hidden key3. Original dataset contents are never passed to the replay model by its file tools.

The window shows:

* **Hidden keys:** three rows showing whether each original hidden key is intact and what happened to its shadow copy. Affected keys are highlighted and listed first. The status line reports integrity of these three keys only; the underlying replay still checks every virtual file.
* **Agent actions:** actual Gemini function calls and their simulated effects, with an action count. Select a row to see the file, link and decoy involved. A malicious link may itself trigger a registered upload/delete operation; the evidence distinguishes that from a direct upload/delete request by Gemini.
* **Captured transfers:** the simulated attacker inbox, containing virtual uploads and email sends with matching decoy tokens and a transfer count. Destinations are display-only strings; no real request, upload or email is sent there. A page visit alone is not a transfer.
* **Agent response:** Gemini's actual final response. Decoys repeated in the response are flagged separately from captured uploads/sends.
* **Key verification:** before/after hashes for the three original hidden keys and worker cleanup status. This does not attest to the rest of the Windows computer.

Completed results show their saved time in your local timezone. Their file verification describes the state at that replay, not a continuous monitor. Reopening a saved result makes no API call. Replay again clears the old evidence display and starts a fresh run; closing an active replay stops it and waits for cleanup before closing the window.

Gemini may refuse malicious instructions, finish without tools, or fail due to an API error. The view records those outcomes without inventing damage, leakage or a successful attack. Opening a decoy key is not proof of exfiltration. A replay is a new model invocation, not a deterministic reproduction of what the stopped worker would have done. Limits are six model turns, eight tool operations and 160 seconds. **Stop** kills and reaps the replay worker while retaining partial evidence.

Original keys remain local; decoy values and public virtual document text can be included in Gemini API requests during replay. No replay tool maps a virtual path onto a host file, runs code, opens a real browser or contacts an attacker destination. This is a controlled virtual simulation, not an OS isolation boundary. Up to 50 completed/partial reports are retained locally until Clear is used.

For a short demo: let an email reach Quarantine, open Investigate, select an observed action, show its decoy or changed shadow file, and finish with the intact original-file hashes. If Gemini refuses a document injection, present that refusal honestly; other link scenarios can still demonstrate the consequences of navigation in this controlled simulation.

## Three separate Gemini conversations

1. **Writer:** writes fresh correspondence and natural link labels using a supplied simulated URL when relevant. Hidden-tool scenarios use a neutral writing prompt. Social-phishing scenarios supply a fictional goal and tone. Neither supplies secret values or private file paths.
2. **Security reviewer:** receives the email, public/protected file manifests, a trusted inspection of the simulated link's requested operation, and untrusted public-document preview text. The inspection never reads protected file contents or executes the requested action. The reviewer has its own security instruction, no tools, no prior conversation, and no generator scenario or attack label.
3. **Summariser:** waits in a separate Python process until the reviewer returns a valid safe verdict. It then receives only the email and public-file manifest. It can request public virtual documents through the Python broker.

These are separate API requests/conversations using the configured Gemini model and key, not three locally hosted LLMs. The application and tool enforcement run locally; inference runs on Google's servers.

If security returns malicious or local phrase checks find an explicit high-risk request, Python kills and reaps the waiting summariser process and moves the email to Quarantine. If security approves but the summariser requests a protected file, upload, deletion, message send, unknown tool, phishing landing page, or a link with those operations, Python independently blocks the action and quarantines the email. Document text is also scanned before tool results reach the summariser. Generator labels never determine the security verdict. Tests explicitly simulate a mistaken safe verdict to exercise these independent controls. The local route inspection is a deliberately inspectable simulation, not a real browser exploit or a claim that a remote URL can access arbitrary Windows files.

API failures or invalid security responses hold the email in Inbox and retry automatically after 60, 120, 240, then 300 seconds while the app is open, or longer when Gemini supplies a quota reset delay. They never allow summarisation without security approval. A generation failure displays an error; another Compose click starts a new generation request. No API errors silently invoke a local model or template. A safe email normally uses at least three requests (writer, security, summary), plus any document-reading turns; daily API quotas therefore limit demo volume.

## Scope

This is a Windows-style simulation, **not a VM, Windows security sandbox or system-wide antivirus**. Subprocesses run with the user's OS permissions; isolation is through fixed application tools, not an OS access-control boundary. No model-generated code is executed. The virtual filesystem never maps arbitrary paths onto host files. Email delivery and browser content are simulated. No real email is sent, and phishing destinations are never contacted.

The Gemini reviewer can misclassify emails. The broker provides an independent enforcement layer for the tools exposed here, not protection for arbitrary external agents or applications. The 30% setting controls the requested generation scenario, not the observed quarantine rate.

Local state lives in `data/mini_pc.json`. It contains fictional secrets in plaintext plus email/summary/incident history. The v1-to-v2 upgrade clears old demo mail and creates the new hidden-key files once, as requested; future launches preserve new emails. Close the app before replacing its state file. Do not put real secrets into this demo.

## Source map

| File | Purpose |
|---|---|
| `dashboard.py` | Native desktop, automatic queue, Compose and three mail tabs |
| `mail_ai.py` | Fresh-email writer and independent Gemini security reviewer |
| `phishing.py` | Ten fictional phishing profiles, varied reserved-domain links, normalisation and contextual phrase rules |
| `gemini_client.py` | Gemini REST, bounded model failover, conversation handoff, structured responses and credential-safe errors |
| `runner.py` | Security-first orchestration, process supervision, retries, quarantine |
| `agent.py` | Gemini summariser worker and function-call requests |
| `broker.py` | Virtual-file and link tool interception |
| `simulation.py` | Fictional filesystem and persisted mail folders |
| `datasets.py` | Synthetic customer/payroll records, public briefs, random identities and structured CSV decoys |
| `shadow.py` | Disposable decoys, simulated capture sink, replay supervisor and integrity comparison |
| `shadow_view.py` | Separate investigation window and saved replay evidence |
| `hyperlinks.py` | Restricted link parsing for the native email reader |
| `security.py` | URL checks and latched denial |

`tools.py` contains an optional real-fetch helper, not used by the mini desktop, with DNS filtering, TLS validation and redirect checks. `documents.py` is a bounded document-import utility; the current Compose flow uses Gemini-generated mail.

Run tests with `python -m unittest discover -s tests -v`. Tests use explicit mocked model replies and test-only worker fixtures; this is not an application offline mode. They verify classification boundaries, role separation, automatic routing, actual process termination, retained quarantine, retry safety, tool enforcement, decoy isolation, replay cancellation, simulated captures, deletion, persistence and honest no-action/error outcomes.

API references: [Gemini GenerateContent](https://ai.google.dev/api/generate-content) and [function calling](https://ai.google.dev/gemini-api/docs/function-calling).
