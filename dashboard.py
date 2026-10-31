"""Automatic, online-only Gemini mail lab inside a native mini desktop."""
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

from mail_ai import create_email
from runner import AgentRun
from simulation import MiniPC
from broker import Broker
from security import SecurityViolation
from hyperlinks import parse_links
from shadow_view import Investigation
from gemini_client import api_session
import ui_theme as theme
from ui_theme import BG, WHITE, INK, MUTED, BLUE, SELECTED, Button, Panel



class Desktop(tk.Tk):
    def __init__(self):
        super().__init__()
        theme.setup(self)
        self.title('AgentShield | Mini PC')
        width, height = min(1280, self.winfo_screenwidth()-70), min(800, self.winfo_screenheight()-80)
        self.geometry(f'{width}x{height}+20+20')
        self.minsize(min(1040, width), min(660, height))
        self.configure(bg=BG)
        self.pc = MiniPC()
        self.events = queue.Queue()
        self.run_handle = None
        self.investigation = None
        self.generating = False
        self.clearing = False
        self.closing = False
        self.folder = 'inbox'
        self.selected = None
        self.status = tk.StringVar(value='Ready')
        self.show_original = False
        self.build()
        self.refresh()
        self.poll_id = self.after(100, self.drain)
        self.protocol('WM_DELETE_WINDOW', self.close)

    def label(self, parent, text, size=10, color=INK, bold=False, **kwargs):
        return tk.Label(parent, text=text, font=(theme.FONT, size, 'bold' if bold else 'normal'),
            bg=parent.cget('bg'), fg=color, **kwargs)

    def button(self, parent, text, command, primary=False):
        return Button(parent, text, command, primary)

    def build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        header = tk.Frame(self, bg=BG, padx=24, pady=14)
        header.grid(row=0, column=0, sticky='ew')
        mark = tk.Canvas(header, width=34, height=34, bg=BG, highlightthickness=0)
        mark.pack(side='left', padx=(0, 10))
        mark.create_polygon(17,3,30,8,28,22,17,32,6,22,4,8, fill='#ea4335', outline='')
        mark.create_line(10,16,15,21,24,12, fill=WHITE, width=3)
        self.label(header, 'AgentShield', 22, MUTED).pack(side='left')
        avatar = tk.Canvas(header, width=36, height=36, bg=BG, highlightthickness=0)
        avatar.pack(side='right')
        avatar.create_oval(1,1,35,35, fill=theme.RED, outline='')
        avatar.create_text(18,18, text=self.pc.state['account']['address'][0].upper(), fill=WHITE, font=(theme.FONT,14))
        self.progress = tk.Label(header, text='', bg=BG, fg=MUTED, font=(theme.FONT,10), wraplength=480)
        self.progress.pack(side='right', padx=20)
        self.status.trace_add('write', lambda *_: self.progress.configure(
            text='' if self.status.get() in ('Ready', 'Cleared', 'Summary ready', 'Moved to Quarantine') else self.status.get()))
        body = tk.Frame(self, bg=BG, padx=12, pady=4)
        body.grid(row=1, column=0, sticky='nsew')
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)
        sidebar = tk.Frame(body, bg=BG, width=208, padx=4, pady=4)
        sidebar.grid(row=0, column=0, sticky='ns', padx=(0, 12))
        sidebar.pack_propagate(False)
        self.compose_button = self.button(sidebar, 'Compose', self.compose, True)
        self.compose_button.configure(pady=18, padx=24)
        self.compose_button.pack(anchor='w', pady=(0, 20))
        self.tabs = {}
        for key, title in [('inbox', 'Inbox'), ('summaries', 'Summary'), ('quarantine', 'Quarantine')]:
            button = self.button(sidebar, title, lambda k=key: self.show_folder(k))
            button.configure(anchor='w', pady=9)
            button.pack(fill='x', pady=1)
            self.tabs[key] = button
        keys_button = self.button(sidebar, 'Hidden keys', lambda: self.explorer(True))
        keys_button.configure(anchor='w')
        keys_button.pack(fill='x', pady=(24, 0))
        panel = Panel(body)
        panel.grid(row=0, column=1, sticky='nsew', pady=(0, 12))
        main = panel.body
        main.columnconfigure(0, weight=1)
        main.rowconfigure(2, weight=1)
        actions = tk.Frame(main, bg=WHITE)
        actions.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        actions.columnconfigure(0, weight=1)
        self.folder_title = self.label(actions, 'Inbox', 18)
        self.folder_title.grid(row=0, column=0, sticky='w', padx=12)
        self.clear_button = self.button(actions, 'Clear', self.clear_messages)
        self.clear_button.configure(fg=theme.RED)
        self.clear_button.grid(row=0, column=1, sticky='e', padx=(12, 0))
        table_frame = tk.Frame(main, bg=WHITE)
        table_frame.grid(row=1, column=0, sticky='ew')
        table_frame.columnconfigure(0, weight=1)
        self.table = theme.Table(table_frame, columns=('subject', 'sender', 'status'),
                                  displaycolumns=('sender', 'subject', 'status'), show='tree', height=4)
        self.table.column('#0', width=0, stretch=False)
        for col, title, width in [('subject', 'Subject', 340), ('sender', 'From', 220), ('status', 'State', 130)]:
            self.table.heading(col, text=title)
            self.table.column(col, width=width, minwidth=80)
        self.table.grid(row=0, column=0, sticky='ew')
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.table.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.bind('<<TreeviewSelect>>', self.select_mail, add='+')
        self.table.tag_configure('pending', font=(theme.FONT, 10, 'bold'), background=WHITE)
        self.table.tag_configure('quarantined', background='#fff6f5')
        self.mail_body = ScrolledText(main, height=10, width=50, wrap='word', bg=WHITE, fg=INK,
            relief='flat', font=(theme.FONT, 11), padx=24, pady=20, spacing1=2, spacing3=2,
            highlightthickness=0, insertbackground=INK)
        self.mail_body.tag_configure('subject', font=(theme.FONT, 20), spacing3=16)
        self.mail_body.tag_configure('metadata', font=(theme.FONT, 10), foreground=MUTED)
        self.mail_body.grid(row=2, column=0, sticky='nsew', pady=12)
        tk.Frame(main, bg=theme.LINE, height=1).grid(row=2, column=0, sticky='new')
        tk.Frame(actions, bg=theme.RED, height=3, width=100).grid(row=1, column=0, sticky='w', padx=12, pady=(8, 0))
        controls = tk.Frame(main, bg=WHITE)
        controls.grid(row=3, column=0, sticky='ew')
        self.original_button = self.button(controls, 'View original', self.toggle_original)
        self.details_button = self.button(controls, 'Details', self.incident_details)
        self.investigate_button = self.button(controls, 'Investigate', self.investigate, True)
        self.details_button.pack(side='right')

    @staticmethod
    def set_text(widget, text):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.configure(state='disabled')

    def refresh(self, select_id=None):
        selected = select_id or (self.selected['id'] if self.selected else None)
        self.table.configure(displaycolumns=('sender', 'subject', 'status') if self.folder == 'inbox' else ('sender', 'subject'))
        self.table.delete(*self.table.get_children())
        for mail in reversed(self.pc.state[self.folder]):
            self.table.insert('', 'end', iid=mail['id'], values=(mail['subject'], mail['sender'], mail['status'].replace('_', ' ')),
                              tags=('pending',) if self.folder == 'inbox' else ('quarantined',) if self.folder == 'quarantine' else ())
        for key, title in [('inbox', 'Inbox'), ('summaries', 'Summary'), ('quarantine', 'Quarantine')]:
            self.tabs[key].configure(text=f'{title}  {len(self.pc.state[key])}',
                bg=(theme.SOFT_RED if key == 'quarantine' else SELECTED) if key == self.folder else BG,
                fg=theme.RED if key == 'quarantine' else INK,
                font=(theme.FONT, 10, 'bold' if key == self.folder else 'normal'))
            if key == self.folder:
                self.folder_title.configure(text=title)
        ids = self.table.get_children()
        if ids:
            selected = selected if selected in ids else ids[0]
            self.table.selection_set(selected)
            self.table.see(selected)
            self.select_mail()
        else:
            self.selected = None
            self.set_text(self.mail_body, 'No messages.')
        self.details_button.pack_forget()
        self.investigate_button.pack_forget()
        self.original_button.pack_forget()
        if self.selected and self.folder == 'quarantine':
            self.details_button.pack(side='right')
            self.investigate_button.pack(side='right', padx=8)
        elif self.selected and self.folder == 'summaries':
            self.original_button.pack(side='right')

    def show_folder(self, folder):
        self.folder = folder
        self.selected = None
        self.show_original = False
        self.refresh()

    def clear_messages(self):
        if self.clearing or self.closing:
            return
        self.clearing = True
        self.clear_button.configure(state='disabled', text='Clearing…')
        self.compose_button.configure(state='disabled')
        self.status.set('Clearing… stopping active work')
        if self.run_handle:
            self.run_handle.stop()
        if self.investigation:
            self.investigation.close()
        self.finish_clear()

    def finish_clear(self):
        if not self.clearing:
            return
        # Wait for all writers to finish before removing state. Late results are
        # drained but ignored while clearing, and no new work can start.
        if self.run_handle and self.run_handle.thread and not self.run_handle.thread.is_alive():
            self.run_handle = None
        if self.generating or self.run_handle or self.investigation:
            self.status.set('Clearing… waiting for the current request to stop')
            return
        # All producers have settled; discard any last queued status/completion.
        while True:
            try:
                self.events.get_nowait()
            except queue.Empty:
                break
        try:
            self.pc.clear_mail()
        except OSError:
            self.clearing = False
            self.clear_button.configure(state='normal', text='Clear')
            self.compose_button.configure(state='normal', text='Compose')
            self.status.set('Could not save cleared mailbox. Please try Clear again.')
            return
        self.clearing = False
        self.selected = None
        self.show_original = False
        self.refresh()
        self.clear_button.configure(state='normal', text='Clear')
        self.compose_button.configure(state='normal', text='Compose')
        self.status.set('Cleared')

    def select_mail(self, _event=None):
        selection = self.table.selection()
        if not selection:
            return
        old_id = self.selected['id'] if self.selected else None
        self.selected = next((m for m in self.pc.state[self.folder] if m['id'] == selection[0]), None)
        if not self.selected:
            return
        mail = self.selected
        if old_id != mail['id']:
            self.show_original = False
        self.original_button.configure(text='View summary' if self.show_original else 'View original')
        if self.folder == 'summaries' and not self.show_original:
            self.set_text(self.mail_body, mail['subject'] + '\n\n' + mail['summary'])
            self.mail_body.tag_add('subject', '1.0', '1.end')
            return
        self.render_email(mail)

    def toggle_original(self):
        self.show_original = not self.show_original
        self.select_mail()

    def render_email(self, mail):
        widget = self.mail_body
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        for tag in widget.tag_names():
            if tag.startswith('email_link_'):
                widget.tag_delete(tag)
        widget.insert('end', mail['subject'] + '\n', 'subject')
        widget.insert('end', f"{mail['sender']}\nTo: {mail['recipient']}\n\n", 'metadata')
        text, cursor = mail['body'], 0
        for index, link in enumerate(parse_links(text)):
            widget.insert('end', text[cursor:link['start']])
            tag = 'email_link_' + str(index)
            widget.insert('end', link['label'], tag)
            widget.tag_configure(tag, foreground=BLUE, underline=True)
            widget.tag_bind(tag, '<Button-1>', lambda event, url=link['url']: self.open_link(url))
            widget.tag_bind(tag, '<Enter>', lambda event: widget.configure(cursor='hand2'))
            widget.tag_bind(tag, '<Leave>', lambda event: widget.configure(cursor='arrow'))
            cursor = link['end']
        widget.insert('end', text[cursor:])
        if mail.get('error'):
            widget.insert('end', '\n\nProcessing paused. ' + mail['error'])
        widget.configure(state='disabled')

    def open_link(self, url):
        if not self.selected:
            return
        broker = Broker(self.pc, self.selected)
        try:
            result = broker.dispatch('open_link', {'url': url})
        except SecurityViolation:
            reason = broker.incident['reason'] if broker.incident else 'Access was blocked.'
            if broker.incident and broker.incident.get('affected_files'):
                reason += '\n\nFile: ' + ', '.join(file['label'] for file in broker.incident['affected_files'])
            messagebox.showinfo('Link blocked', reason, parent=self)
            return
        window = self.popup(result.get('title', 'Document'))
        content = ScrolledText(window, wrap='word', font=(theme.FONT, 11), bg=WHITE, relief='flat', padx=22, pady=22)
        content.pack(fill='both', expand=True)
        self.set_text(content, result['content'])

    def compose(self):
        if self.generating or self.clearing or self.closing:
            return
        self.generating = True
        self.compose_button.configure(state='disabled', text='Writing…')
        self.status.set('Writing email…')
        def work():
            try:
                with api_session(self.events.put):
                    self.events.put(dict(event='mail_created', mail=create_email(self.pc)))
            except Exception as error:
                self.events.put(dict(event='generation_error', message=str(error) if isinstance(error, RuntimeError) else type(error).__name__ + ': Gemini connection failed'))
        threading.Thread(target=work, daemon=True).start()

    def start_next(self):
        if self.run_handle or self.closing or self.clearing:
            return
        mail = next((m for m in self.pc.state['inbox'] if m['status'] in ('queued', 'waiting_retry')
                     and m.get('retry_at', 0) <= time.time()), None)
        if mail:
            self.run_handle = AgentRun(self.pc, mail, self.events.put)
            self.run_handle.start()

    def popup(self, title, width=800, height=540):
        window = tk.Toplevel(self)
        window.title(title + ' | AgentShield mini PC')
        window.geometry(f'{min(width, self.winfo_screenwidth()-80)}x{min(height, self.winfo_screenheight()-100)}')
        window.configure(bg=WHITE)
        window.transient(self)
        return window

    def explorer(self, only_secrets=False, datasets_only=False):
        title = 'Business data' if datasets_only else 'Hidden keys' if only_secrets else 'Files'
        window = self.popup(title)
        self.label(window, title, 17, bold=True).pack(anchor='w', padx=20, pady=16)
        listing = tk.Listbox(window, height=6, font=(theme.FONT, 11), bg=BG, fg=INK, bd=0, highlightthickness=0,
                             selectbackground=SELECTED, selectforeground=INK)
        listing.pack(fill='x', padx=20, pady=12)
        files = self.pc.state['files']
        if datasets_only:
            files = [f for f in files if f.get('dataset') and f['secret']]
        elif only_secrets:
            files = [f for f in files if f['secret'] and not f.get('dataset')]
        for file in files:
            listing.insert('end', file['label'])
        content = ScrolledText(window, wrap='word', font=('Consolas', 10), bg=WHITE, relief='flat', padx=12, pady=12)
        content.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        def select(_event=None):
            if listing.curselection():
                file = files[listing.curselection()[0]]
                note = '\nFictional demo records' if file.get('dataset') and file['secret'] else ''
                self.set_text(content, file['label'] + '\n' + file['path'] + note + '\n\n' + file['content'])
        listing.bind('<<ListboxSelect>>', select)
        listing.selection_set(0)
        select()

    @staticmethod
    def incident_text(incident):
        names = {'hidden_key_access': 'Protected file access', 'data_upload': 'Data upload',
                 'phishing_language': 'Phishing language detected', 'phishing_link': 'Phishing destination',
                 'protected_data_access': 'Confidential business data access',
                 'file_deletion': 'File deletion', 'document_injection': 'Instructions hidden in a document',
                 'unauthorised_message': 'Unauthorised message'}
        heading = names.get(incident.get('category'), 'Blocked request')
        text = heading + '\n\n' + incident['reason'] + '\n\nAction blocked. The summariser was stopped.'
        for signal in incident.get('text_signals', []):
            text += '\n\n' + signal['reason'] + ' (' + signal['severity'] + ')\nMatched wording: ' + signal['matched']
        if incident.get('category') == 'phishing_link':
            text += '\n\nLink: ' + incident.get('target', '')
        affected = incident.get('affected_files') or incident['secrets']
        for file in affected:
            text += '\n\nFile: ' + file['label'] + '\n' + file['path']
        if incident.get('destination'):
            text += '\n\nDestination: ' + incident['destination']
        for secret in incident['secrets']:
            text += '\n\nProtected contents of ' + secret['label'] + ':\n' + secret['preview']
        return text

    def incident_details(self):
        incident = next((i for i in reversed(self.pc.state['incidents']) if self.selected and i['email_id'] == self.selected['id']), None)
        if not incident:
            return
        window = self.popup('Quarantine details')
        content = ScrolledText(window, wrap='word', font=(theme.FONT, 11), bg=WHITE, fg=INK, relief='flat', padx=20, pady=20)
        content.pack(fill='both', expand=True)
        self.set_text(content, self.incident_text(incident))

    def shadow_busy(self):
        return self.investigation is not None and self.investigation.run_handle is not None

    def investigate(self):
        if self.clearing or not self.selected or self.folder != 'quarantine':
            return
        if self.investigation:
            if self.shadow_busy() or self.investigation.mail['id'] == self.selected['id']:
                self.investigation.lift()
                return
            self.investigation.close()
        self.investigation = Investigation(self, self.selected)

    def drain(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event['event']
                if self.clearing:
                    if kind in ('mail_created', 'generation_error'):
                        self.generating = False
                    # Other events can still arrive until the worker thread exits.
                    # Keep its handle until then, so clearing cannot race a save.
                    continue
                if kind == 'model_status':
                    self.status.set(event['message'])
                elif kind in ('mail_created', 'generation_error'):
                    self.generating = False
                    self.compose_button.configure(state='normal', text='Compose')
                    if kind == 'mail_created':
                        mail = event['mail']
                        self.pc.state['inbox'].append(mail)
                        self.pc.save()
                        self.folder = 'inbox'
                        self.refresh(mail['id'])
                    else:
                        self.status.set('Email generation failed')
                        messagebox.showerror('Gemini could not compose an email', event['message'], parent=self)
                elif kind in ('checking', 'summarising'):
                    self.status.set('Checking email…' if kind == 'checking' else 'Summarising…')
                    self.refresh()
                elif kind in ('quarantined', 'complete'):
                    self.folder = 'quarantine' if kind == 'quarantined' else 'summaries'
                    self.status.set('Moved to Quarantine' if kind == 'quarantined' else 'Summary ready')
                    self.refresh(event['mail_id'])
                elif kind == 'error':
                    self.status.set('Waiting to retry')
                    self.refresh()
                elif kind == 'finished':
                    self.run_handle = None
        except queue.Empty:
            pass
        if self.clearing:
            self.finish_clear()
        else:
            self.start_next()
        self.clear_button.configure(state='disabled' if self.clearing else 'normal')
        self.poll_id = self.after(100, self.drain)

    def close(self):
        self.closing = True
        self.after_cancel(self.poll_id)
        if self.run_handle:
            self.run_handle.stop()
        if self.shadow_busy():
            self.investigation.run_handle.stop()
            # Give the bounded cleanup a chance to save the final evidence before Python exits.
            self.investigation.run_handle.thread.join(timeout=6)
        self.destroy()


if __name__ == '__main__':
    Desktop().mainloop()
