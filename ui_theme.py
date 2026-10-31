"""Small native widgets for the mail interface; no browser or extra dependency."""
from pathlib import Path
import sys
import tkinter as tk
from tkinter import font as tkfont, ttk

BG, WHITE, INK, MUTED = '#d3d3d0', '#f1f1ef', '#1f1f1f', '#444746'
BLUE, RED, SOFT_RED = '#0b57d0', '#b3261e', '#fce8e6'
SELECTED, COMPOSE, LINE = '#fff0bf', '#fce8a6', '#aaa9a4'
FONT = 'Google Sans'

if sys.platform == 'win32':
    import ctypes
    # Private to this process; no system installation or registry changes.
    for path in (Path(__file__).parent / 'assets' / 'fonts').glob('*.ttf'):
        ctypes.windll.gdi32.AddFontResourceExW(str(path.resolve()), 0x10, None)


def setup(root):
    global FONT
    families = tkfont.families(root)
    FONT = next((name for name in ('Google Sans', 'Google Sans Text', 'Roboto', 'Segoe UI') if name in families), 'Arial')
    root.option_add('*Font', (FONT, 10))
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('Treeview', font=(FONT, 10), rowheight=38, background='#f5f5f3',
                    fieldbackground=WHITE, foreground=INK, borderwidth=0, lightcolor=WHITE, darkcolor=WHITE)
    style.configure('Treeview.Heading', font=(FONT, 10, 'bold'), background='#ecece9', foreground=INK,
                    relief='flat', borderwidth=0, padding=(10, 10))
    style.map('Treeview', background=[('selected', SELECTED)], foreground=[('selected', INK)])
    style.map('Treeview.Heading', background=[('active', BG)])
    style.layout('Treeview', [('Treeview.treearea', {'sticky': 'nswe'})])
    style.configure('TNotebook', background=WHITE, borderwidth=0)
    style.configure('TNotebook.Tab', font=(FONT, 10), background=WHITE, foreground=MUTED,
                    padding=(16, 12), borderwidth=0)
    style.map('TNotebook.Tab', background=[('selected', SOFT_RED)], foreground=[('selected', RED)],
              padding=[('selected', (16, 12)), ('!selected', (16, 12))])
    style.configure('Vertical.TScrollbar', background='#dadce0', troughcolor=WHITE,
                    borderwidth=0, arrowsize=12, lightcolor=WHITE, darkcolor=WHITE)


class Table(ttk.Treeview):
    """Native table with Gmail-like horizontal dividers, including on scroll."""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self._line_job = None
        self._lines = []
        self._marker = tk.Frame(self, bg=RED, takefocus=False)
        self._top = tk.Frame(self, bg=LINE, height=1, takefocus=False)
        self._top.place(x=0, y=0, relwidth=1)
        for event in ('<Configure>', '<Expose>', '<MouseWheel>', '<ButtonRelease-1>', '<<TreeviewSelect>>', '<KeyRelease>'):
            self.bind(event, self.redraw_later, add='+')

    def redraw_later(self, *_):
        if self._line_job is None:
            self._line_job = self.after_idle(self.draw_lines)

    def draw_lines(self):
        self._line_job = None
        visible = [(iid, self.bbox(iid)) for iid in self.get_children()]
        visible = [(iid, box) for iid, box in visible if box and box[1] < self.winfo_height()]
        while len(self._lines) < len(visible):
            self._lines.append(tk.Frame(self, bg=LINE, height=1, takefocus=False))
        for index, (iid, (_x, y, _width, height)) in enumerate(visible):
            line = self._lines[index]
            line.place(x=0, y=y+height-1, relwidth=1, height=1)
            line.bind('<Button-1>', lambda _e, row=iid: self.select_row(row))
            line.bind('<MouseWheel>', lambda e: self.event_generate('<MouseWheel>', delta=e.delta))
        for line in self._lines[len(visible):]:
            line.place_forget()
        selected = self.selection()
        box = self.bbox(selected[0]) if selected else ()
        if box:
            self._marker.place(x=0, y=box[1], width=3, height=box[3]-1)
        else:
            self._marker.place_forget()

    def select_row(self, row):
        self.selection_set(row)
        self.focus(row)
        self.focus_set()

    def insert(self, *args, **kwargs):
        result = super().insert(*args, **kwargs)
        self.redraw_later()
        return result

    def delete(self, *args):
        result = super().delete(*args)
        self.redraw_later()
        return result

    def yview(self, *args):
        result = super().yview(*args)
        self.redraw_later()
        return result

    def see(self, item):
        result = super().see(item)
        self.redraw_later()
        return result

    def destroy(self):
        if self._line_job is not None:
            self.after_cancel(self._line_job)
        super().destroy()


def rounded(canvas, x1, y1, x2, y2, radius, **options):
    r = min(radius, (x2-x1)/2, (y2-y1)/2)
    return canvas.create_polygon(x1+r,y1,x2-r,y1,x2,y1,x2,y1+r,x2,y2-r,x2,y2,
                                 x2-r,y2,x1+r,y2,x1,y2,x1,y2-r,x1,y1+r,x1,y1,
                                 smooth=True, splinesteps=24, **options)


class Button(tk.Canvas):
    """Rounded control with mouse, keyboard, disabled state and normal button API."""
    def __init__(self, parent, text, command, primary=False):
        self.options = dict(text=text, command=command, bg=COMPOSE if primary else parent.cget('bg'),
                            fg='#463500' if primary else INK, state='normal', font=(FONT, 10),
                            padx=18, pady=11, anchor='center')
        self.hover = False
        super().__init__(parent, bg=parent.cget('bg'), highlightthickness=0, bd=0, takefocus=True, cursor='hand2')
        self.text_font = tkfont.Font(self, font=self.options['font'])
        self.bind('<Configure>', lambda _e: self.draw())
        self.bind('<Enter>', lambda _e: self.highlight(True))
        self.bind('<Leave>', lambda _e: self.highlight(False))
        self.bind('<FocusIn>', lambda _e: self.draw())
        self.bind('<FocusOut>', lambda _e: self.draw())
        self.bind('<ButtonRelease-1>', self.clicked)
        self.bind('<Return>', lambda _e: self.invoke())
        self.bind('<space>', lambda _e: self.invoke())
        self.resize()

    def configure(self, cnf=None, **kwargs):
        if cnf:
            kwargs.update(cnf)
        for key in list(kwargs):
            if key in self.options:
                self.options[key] = kwargs.pop(key)
        if kwargs:
            super().configure(**kwargs)
        self.resize()

    config = configure

    def cget(self, key):
        return self.options[key] if key in self.options else super().cget(key)

    __getitem__ = cget

    def resize(self):
        self.text_font.configure(family=self.options['font'][0], size=self.options['font'][1],
                                 weight=self.options['font'][2] if len(self.options['font']) > 2 else 'normal')
        super().configure(width=self.text_font.measure(self.options['text']) + 2*self.options['padx'],
                          height=self.text_font.metrics('linespace') + 2*self.options['pady'],
                          takefocus=self.options['state'] != 'disabled')
        self.draw()

    def draw(self):
        self.delete('all')
        w, h = max(self.winfo_width(), 2), max(self.winfo_height(), 2)
        disabled = self.options['state'] == 'disabled'
        fill = self.options['bg']
        if self.hover and not disabled:
            fill = '#ffe69a' if fill in (SELECTED, COMPOSE) else '#f7d6d2' if fill == SOFT_RED else '#e9e9e5'
        rounded(self, 1, 1, w-1, h-1, 16, fill=fill,
                outline=RED if self.focus_get() == self and not disabled else fill, width=2)
        left = self.options['anchor'] == 'w'
        self.create_text(self.options['padx'] if left else w/2, h/2, text=self.options['text'],
                         anchor='w' if left else 'center', font=self.text_font,
                         fill='#80868b' if disabled else self.options['fg'])

    def highlight(self, value):
        self.hover = value
        self.draw()

    def clicked(self, event):
        if 0 <= event.x < self.winfo_width() and 0 <= event.y < self.winfo_height():
            self.invoke()

    def invoke(self):
        if self.options['state'] != 'disabled':
            return self.options['command']()

    def destroy(self):
        super().destroy()
        # Tk resources must be released on the UI thread, even if a background
        # thread later garbage-collects the Python widget/command reference cycle.
        del self.text_font


class Panel(tk.Canvas):
    def __init__(self, parent):
        super().__init__(parent, bg=parent.cget('bg'), highlightthickness=0, bd=0)
        self.body = tk.Frame(self, bg=WHITE)
        self.window = self.create_window(14, 14, window=self.body, anchor='nw')
        self.bind('<Configure>', self.resize)

    def resize(self, event):
        self.delete('surface')
        rounded(self, 1, 1, event.width-1, event.height-1, 20, fill=WHITE, outline=LINE, tags='surface')
        self.tag_lower('surface')
        self.itemconfigure(self.window, width=max(1, event.width-28), height=max(1, event.height-28))
