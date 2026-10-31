"""Investigation window, kept separate from the everyday mail reader."""
import queue
from datetime import datetime
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

from shadow import ShadowRun, findings
import ui_theme as theme
from ui_theme import BG, WHITE, INK, MUTED

TOOL_LABELS = dict(open_link='Open link', read_file='Read file', upload_file='Upload file',
                   delete_file='Delete file', send_email='Send email')
HIDDEN_KEYS = {'hidden key1', 'hidden key2', 'hidden key3'}


def local_time(value):
    try:
        return datetime.fromisoformat(value).astimezone().strftime('%d %b, %I:%M %p')
    except (ValueError, TypeError):
        return value or 'Unknown time'


class Investigation(tk.Toplevel):
    def __init__(self, desktop, mail):
        super().__init__(desktop)
        self.desktop, self.mail = desktop, mail
        self.events, self.run_handle, self.report = queue.Queue(), None, None
        self.closing_view = False
        self.title('Shadow PC | AgentShield')
        self.geometry(f'{min(1100, self.winfo_screenwidth()-80)}x{min(790, self.winfo_screenheight()-100)}')
        self.minsize(850, 580)
        self.configure(bg=BG)
        self.transient(desktop)
        self.protocol('WM_DELETE_WINDOW', self.close)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
        header = tk.Frame(self, bg=BG, padx=24, pady=16)
        header.grid(row=0, column=0, sticky='ew')
        tk.Label(header, text='Shadow PC', font=(theme.FONT, 22), bg=BG, fg=INK).pack(side='left')
        self.replay_button = desktop.button(header, 'Replay', self.start, True)
        self.replay_button.pack(side='right', padx=4)
        self.stop_button = desktop.button(header, 'Stop', self.stop)
        self.stop_button.pack(side='right', padx=4)
        self.stop_button.configure(state='disabled')

        intro = tk.Frame(self, bg=BG, padx=20, pady=10)
        intro.grid(row=1, column=0, sticky='ew')
        tk.Label(intro, text=mail['subject'], font=(theme.FONT, 14), bg=BG, fg=INK,
                 anchor='w', wraplength=900).pack(fill='x')
        self.status = tk.StringVar(value='Preparing replay…')
        self.status_label = tk.Label(intro, textvariable=self.status, font=(theme.FONT, 10), bg=BG, fg=MUTED)
        self.status_label.pack(anchor='w', pady=(6, 0))
        self.outcome = tk.StringVar()
        self.explanation = tk.StringVar()

        comparison = tk.Frame(self, bg=WHITE, padx=12, pady=10)
        comparison.grid(row=2, column=0, sticky='ew', padx=20)
        tk.Label(comparison, text='Hidden keys', bg=WHITE, fg=INK,
                 font=(theme.FONT, 14)).pack(anchor='w', pady=(0, 10))
        self.files = theme.Table(comparison, columns=('file', 'original', 'shadow'), show='headings', height=3)
        for key, title, width in [('file', 'Key', 250), ('original', 'Original', 160), ('shadow', 'Shadow copy', 300)]:
            self.files.heading(key, text=title, anchor='w')
            self.files.column(key, width=width, minwidth=100)
        self.files.pack(side='left', fill='x', expand=True)
        file_scroll = ttk.Scrollbar(comparison, orient='vertical', command=self.files.yview)
        file_scroll.pack(side='right', fill='y')
        self.files.configure(yscrollcommand=file_scroll.set)

        notebook = self.notebook = ttk.Notebook(self)
        notebook.grid(row=3, column=0, sticky='nsew', padx=20, pady=12)
        trace = tk.Frame(notebook, bg=WHITE, padx=10, pady=10)
        notebook.add(trace, text='Agent actions')
        action_frame = tk.Frame(trace, bg=WHITE)
        action_frame.pack(fill='x')
        self.actions = theme.Table(action_frame, columns=('step', 'tool', 'outcome'), show='headings', height=2)
        for key, title, width in [('step', '#', 40), ('tool', 'Action', 140), ('outcome', 'Result', 620)]:
            self.actions.heading(key, text=title, anchor='w')
            self.actions.column(key, width=width, minwidth=30, stretch=key == 'outcome')
        self.actions.pack(side='left', fill='x', expand=True)
        scrollbar = ttk.Scrollbar(action_frame, orient='vertical', command=self.actions.yview)
        scrollbar.pack(side='right', fill='y')
        self.actions.configure(yscrollcommand=scrollbar.set)
        self.actions.bind('<<TreeviewSelect>>', self.select_action, add='+')
        self.detail = self.text(trace)
        self.captured = self.text(notebook)
        notebook.add(self.captured, text='Captured transfers')
        self.response = self.text(notebook)
        notebook.add(self.response, text='Agent response')
        self.proof = self.text(notebook, monospace=True)
        notebook.add(self.proof, text='Key verification')

        history = [r for r in desktop.pc.state.get('investigations', []) if r['email_id'] == mail['id']]
        if history:
            self.render(history[-1])
            self.replay_button.configure(text='Replay again')
        else:
            self.start()
        self.poll_id = self.after(100, self.drain)

    def text(self, parent, monospace=False):
        text = ScrolledText(parent, wrap='word', font=('Consolas' if monospace else theme.FONT, 10),
                            bg=WHITE, fg=INK, relief='flat', padx=14, pady=12, height=6, width=60)
        # Notebook pages are managed by Notebook.add, not pack.
        if not isinstance(parent, ttk.Notebook):
            text.pack(fill='both', expand=True, pady=(6, 0))
        return text

    def start(self):
        if self.run_handle or self.desktop.closing or self.desktop.clearing or self.closing_view:
            return
        self.status.set('Gemini is replaying the email…')
        self.replay_button.configure(state='disabled', text='Replaying…')
        self.stop_button.configure(state='normal')
        self.run_handle = ShadowRun(self.desktop.pc, self.mail, self.events.put)
        # Clear previous evidence immediately when a fresh replay is requested.
        self.run_handle.publish()
        self.run_handle.start()

    def stop(self):
        if self.run_handle:
            self.status.set('Stopping replay…')
            self.stop_button.configure(state='disabled')
            self.run_handle.stop()

    def render(self, report):
        self.report = report
        state = report['status']
        key_files = [file for file in report['files'] if file['label'] in HIDDEN_KEYS]
        keys_complete = {file['label'] for file in key_files} == HIDDEN_KEYS
        keys_intact = keys_complete and all(file['original'] == 'Intact' for file in key_files)
        integrity = ('Original hidden keys intact' if keys_intact else
                     'Hidden-key changes detected' if keys_complete else 'Hidden-key verification incomplete')
        label = {'running': 'Replaying with Gemini', 'complete': 'Replay complete',
                 'cancelled': 'Replay stopped', 'error': 'Replay incomplete'}.get(state, state)
        if state == 'running' and report.get('connection_status'):
            label = report['connection_status']
        stamp = '' if state == 'running' else ' • Saved result: ' + local_time(report.get('finished', report['created']))
        if report.get('storage_error'):
            stamp = ' • Result not saved'
        if self.run_handle and self.run_handle.cancelled.is_set():
            label = 'Stopping replay…'
        self.status.set(label + ' • ' + integrity + stamp)
        self.status_label.configure(fg='#a33a26' if not keys_intact or state in ('error', 'cancelled') else MUTED)
        title, explanation = findings(report)
        self.outcome.set(title)
        self.explanation.set(explanation)
        self.files.delete(*self.files.get_children())
        affected = lambda f: f['original'] != 'Intact' or f['shadow'] not in ('Unchanged', 'Decoy ready')
        self.files.tag_configure('affected', background=theme.SELECTED, foreground='#624600')
        for file in sorted(key_files, key=lambda f: not affected(f)):
            self.files.insert('', 'end', values=(file['label'], file['original'], file['shadow']),
                              tags=('affected',) if affected(file) else ())
        selected = self.actions.selection()
        self.actions.delete(*self.actions.get_children())
        self.actions.configure(height=min(4, max(2, len(report['events']))))
        self.notebook.tab(0, text=f"Agent actions ({len(report['events'])})")
        self.notebook.tab(1, text=f"Captured transfers ({len(report['captures'])})")
        for event in report['events']:
            self.actions.insert('', 'end', iid=str(event['step']), values=(event['step'], TOOL_LABELS.get(event['tool'], event['tool']), event['outcome']))
        if report['events']:
            iid = selected[0] if selected and self.actions.exists(selected[0]) else str(report['events'][-1]['step'])
            self.actions.selection_set(iid)
            self.actions.see(iid)
            self.select_action()
        else:
            self.desktop.set_text(self.detail, 'Replaying…' if state == 'running' else 'No actions recorded.')

        captures = []
        for index, item in enumerate(report['captures'], 1):
            labels = ', '.join(c['label'] for c in item['canaries']) or 'No decoy token detected'
            captures.append(f"{index}. Simulated {item['kind']}\nDestination: {item['destination']}\n"
                            f"Decoy match: {labels}\n\n{item['content']}")
        self.desktop.set_text(self.captured, '\n\n──────────\n\n'.join(captures) if captures else 'No transfers captured.')
        response = report.get('summary') or ('Waiting for the agent response…' if state == 'running' else 'No final response.')
        if report.get('summary_canaries'):
            response = 'Decoy data appeared in the agent response: ' + ', '.join(c['label'] for c in report['summary_canaries']) + '\n\n' + response
        if report.get('error'):
            response += '\n\nReplay stopped: ' + report['error']
        if report.get('storage_error'):
            response += '\n\n' + report['storage_error']
        self.desktop.set_text(self.response, response)

        proof = f"Replay {report['id']}\nStarted: {report['created']}\n"
        if report.get('finished'):
            proof += f"Finished: {report['finished']}\nWorker ended: {report['process_terminated']}\n"
        proof += '\n' + integrity + '\n'
        for file in key_files:
            proof += f"\n{file['path']}\nBefore: {file['hash'] or 'Not present'}\nAfter:  {file['current_hash'] or 'Missing'}\n{file['original']}\n"
        self.desktop.set_text(self.proof, proof)

    def select_action(self, _event=None):
        selection = self.actions.selection()
        if not selection or not self.report:
            return
        event = next((e for e in self.report['events'] if str(e['step']) == selection[0]), None)
        if event is None:
            return
        text = f"Step {event['step']} · {TOOL_LABELS.get(event['tool'], event['tool'])}\n{event['outcome']}\n\nTarget: {event['target'] or 'None'}"
        if event['effect'] == 'phishing_landing':
            text += '\nThe page was visited only. No login, payment or permission was submitted.'
        if event['tool'] == 'open_link' and event['effect'] in ('upload', 'delete'):
            text += '\nThe simulated link triggered this effect when opened.'
        text += '\nResult returned to the agent: ' + ('Yes' if event.get('response_delivered') else 'No')
        if event.get('destination'):
            text += '\nDestination: ' + event['destination']
        if event['tool'] == 'open_link':
            text += '\nLink requested by Gemini: ' + event['args'].get('url', '')
        for canary in event['canaries']:
            text += f"\n\nDecoy for {canary['label']}:\n{canary['token']}"
        self.desktop.set_text(self.detail, text)

    def drain(self):
        try:
            while True:
                event = self.events.get_nowait()
                self.render(event['report'])
                if event['event'] == 'shadow_finished':
                    self.run_handle = None
                    self.replay_button.configure(state='disabled' if self.closing_view else 'normal', text='Replay again')
                    self.stop_button.configure(state='disabled')
        except queue.Empty:
            pass
        self.poll_id = self.after(100, self.drain)

    def close(self):
        if self.closing_view:
            return
        self.closing_view = True
        self.replay_button.configure(state='disabled')
        self.stop_button.configure(state='disabled')
        if self.run_handle:
            self.run_handle.stop()
            # Keep the window until final cleanup/history save finishes.
            self.status.set('Stopping replay…')
            self.after(100, self.close_when_finished)
            return
        self.finish_close()

    def finish_close(self):
        self.after_cancel(self.poll_id)
        self.desktop.investigation = None
        self.destroy()

    def destroy(self):
        super().destroy()
        self.status = self.outcome = self.explanation = None

    def close_when_finished(self):
        if self.run_handle:
            self.after(100, self.close_when_finished)
        else:
            self.finish_close()
