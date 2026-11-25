"""Tkinter desktop UI; no disk cache, analytics, clipboard export or secret logging."""

import argparse
import queue
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import ttk, messagebox, font
from pydantic import ValidationError
from client.api import VaultAPI, APIError
from client.crypto import VaultIntegrityError
from client.service import VaultService, LockedError
from shared.schemas import PlainRecord


class VaultWindow(tk.Tk):
    def __init__(self, service, timeout=300):
        super().__init__()
        self.service, self.timeout = service, timeout
        self.title("VaultShield · Encrypted Credential Vault")
        self.geometry("1040x780")
        self.minsize(900, 700)
        self.palette = {"page":"#e8eaff", "surface":"#ffffff", "soft":"#dfe3ff", "ink":"#11183f", "muted":"#536184", "primary":"#6554e8", "hover":"#4936cf", "nav":"#101735", "line":"#cbd2ff"}
        self.configure(bg=self.palette["page"])
        available_fonts = {name.casefold(): name for name in font.families(self)}
        self.font_family = next(
            (
                available_fonts[name]
                for name in ("segoe ui", "dejavu sans", "helvetica", "nimbus sans l")
                if name in available_fonts
            ),
            "TkDefaultFont",
        )
        font.nametofont("TkDefaultFont").configure(family=self.font_family, size=11)
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=self.palette["page"])
        style.configure("Card.TFrame", background=self.palette["surface"], relief="flat")
        style.configure("Soft.TFrame", background=self.palette["soft"], relief="flat")
        style.configure("TLabel", background=self.palette["page"], foreground=self.palette["ink"], font=(self.font_family, 10))
        style.configure("Title.TLabel", font=(self.font_family, 27, "bold"), foreground=self.palette["ink"])
        style.configure("Subtitle.TLabel", font=(self.font_family, 10), foreground=self.palette["muted"])
        style.configure("CardTitle.TLabel", background=self.palette["surface"], foreground=self.palette["ink"], font=(self.font_family, 14, "bold"))
        style.configure("CardText.TLabel", background=self.palette["surface"], foreground=self.palette["muted"], font=(self.font_family, 9))
        style.configure("TButton", font=(self.font_family, 9, "bold"), padding=(15, 10), background="#dfe3ff", foreground="#30258f", borderwidth=0, focusthickness=0)
        style.map("TButton", background=[("active", "#c7ccff"), ("pressed", "#b3baff")], foreground=[("active", "#21186e")])
        style.map("TButton", background=[("active", "#d7dcff"), ("pressed", "#c7ceff")])
        style.configure("Accent.TButton", background=self.palette["primary"], foreground="#ffffff", padding=(18, 11), font=(self.font_family, 10, "bold"))
        style.map("Accent.TButton", background=[("active", self.palette["hover"]), ("pressed", "#3730a3")], foreground=[("active", "#ffffff")])
        style.configure("TEntry", padding=11, font=(self.font_family, 10), fieldbackground="#ffffff")
        style.configure("Treeview", font=(self.font_family, 10), rowheight=40, background="#ffffff", fieldbackground="#ffffff", borderwidth=0)
        style.configure("Treeview.Heading", font=(self.font_family, 9, "bold"), background="#e9edff", foreground="#3730a3", padding=12)
        style.map("Treeview", background=[("selected", "#e0e7ff")], foreground=[("selected", "#1e1b4b")])
        self.pool = ThreadPoolExecutor(max_workers=1)
        self.results = queue.Queue()
        self.busy = False
        self.screen_epoch = 0
        self.last_activity = time.monotonic()
        self.secret_vars = []
        header = tk.Frame(self, bg=self.palette["nav"], height=68)
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(header, text="✦  VAULTSHIELD", bg=self.palette["nav"], fg="#ffffff",
                 font=(self.font_family, 14, "bold")).pack(side="left", padx=26)
        tk.Label(header, text="PRIVATE BY DESIGN  •  AES-256-GCM  •  TLS 1.3",
                 bg=self.palette["nav"], fg="#a5b4fc", font=(self.font_family, 9, "bold")).pack(side="right", padx=24)
        self.body = ttk.Frame(self, padding=(38, 30))
        self.body.pack(fill="both", expand=True)
        self.status = tk.StringVar(value="●  Secure local demo ready")
        statusbar = tk.Frame(self, bg="#e0e7ff", height=38)
        statusbar.pack(fill="x")
        tk.Label(statusbar, textvariable=self.status, bg="#e0e7ff", fg="#4338a8",
                 font=(self.font_family, 9)).pack(side="left", padx=20, pady=7)
        self.bind_all("<KeyPress>", self.activity)
        self.bind_all("<ButtonPress>", self.activity)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.show_login()
        self.after(80, self.poll)
        self.after(500, self.tick)

    def card(self, parent, padding=22):
        return ttk.Frame(parent, style="Card.TFrame", padding=padding)

    def action_button(self, parent, text, command, primary=False):
        button = ttk.Button(parent, text=text, command=command, style="Accent.TButton" if primary else "TButton")
        button.configure(cursor="hand2")
        if primary:
            button.bind("<Enter>", lambda _e: button.configure(style="AccentHover.TButton"))
            button.bind("<Leave>", lambda _e: button.configure(style="Accent.TButton"))
        return button

    def activity(self, event=None):
        self.last_activity = time.monotonic()

    def clear(self, heading, subtitle=""):
        self.screen_epoch += 1
        for variable in self.secret_vars:
            variable.set("")
        self.secret_vars.clear()
        for widget in self.body.winfo_children():
            widget.destroy()
        ttk.Label(self.body, text=heading, style="Title.TLabel").pack(anchor="w", pady=(2, 7))
        if subtitle:
            ttk.Label(self.body, text=subtitle, style="Subtitle.TLabel",
                      wraplength=900).pack(anchor="w", pady=(0, 22))

    def field(self, parent, label, value="", secret=False):
        in_card = isinstance(parent, ttk.Frame) and parent.cget("style") == "Card.TFrame"
        ttk.Label(parent, text=label, style="CardText.TLabel" if in_card else "TLabel").pack(anchor="w", pady=(8, 4))
        variable = tk.StringVar(value=value)
        if secret:
            self.secret_vars.append(variable)
        entry = ttk.Entry(parent, textvariable=variable, show="*" if secret else "")
        entry.pack(fill="x")
        return variable, entry

    def run(self, action, success):
        if self.busy:
            return
        self.busy = True
        epoch = self.screen_epoch
        self.status.set("Working securely…")

        def job():
            try:
                result = (True, action())
            except Exception as exc:
                # Only allow explicit safe messages. Do not print exception objects with request data.
                if isinstance(exc, (APIError, VaultIntegrityError, LockedError)):
                    result = (False, (str(exc), getattr(exc, "status", None)))
                elif isinstance(exc, (ValidationError, ValueError)):
                    result = (
                        False,
                        ("Invalid input. Check field lengths and passphrase requirements.", None),
                    )
                else:
                    result = (False, ("Operation failed. Check setup and server availability.", None))
            self.results.put((epoch, result, success))

        self.pool.submit(job)

    def poll(self):
        try:
            epoch, (ok, value), success = self.results.get_nowait()
            self.busy = False
            if epoch == self.screen_epoch:
                self.status.set("Ready · secrets remain in local process memory")
                if ok:
                    success(value)
                else:
                    message, status = value
                    if status == 401:
                        self.service.lock()
                        self.service.api.token = None
                        self.show_login()
                    elif not self.service.user_id:
                        self.show_login()
                    elif self.service.key is None and self.service.vault:
                        self.show_unlock()
                    messagebox.showerror("VaultShield", message, parent=self)
        except queue.Empty:
            pass
        self.after(80, self.poll)

    def tick(self):
        if self.service.key is not None and time.monotonic() - self.last_activity >= self.timeout:
            self.lock_vault()
            self.status.set("Locked after inactivity. Unsaved edits were discarded.")
        self.after(500, self.tick)

    def show_login(self):
        self.clear("Welcome to VaultShield", "A calmer, clearer way to protect your digital credentials. Your account password signs you in; your separate master passphrase unlocks your vault.")
        shell = ttk.Frame(self.body)
        shell.pack(fill="both", expand=True, pady=(8, 10))
        hero = ttk.Frame(shell, style="Soft.TFrame", padding=28)
        hero.pack(side="left", fill="both", expand=True, padx=(0, 18))
        tk.Label(hero, text="✦", bg="#f7f8ff", fg="#6865ed", font=(self.font_family, 34, "bold")).pack(anchor="w", pady=(5, 18))
        tk.Label(hero, text="Your secrets.\nYour control.", bg="#f7f8ff", fg="#172554", justify="left", font=(self.font_family, 25, "bold")).pack(anchor="w")
        tk.Label(hero, text="Encrypted locally with AES-256-GCM\nProtected in transit with verified TLS 1.3", bg="#f7f8ff", fg="#64748b", justify="left", font=(self.font_family, 10), pady=18).pack(anchor="w")
        for label, color in [("AES-256-GCM encryption", "#e0e7ff"), ("Master phrase stays local", "#cffafe"), ("Authenticated server activity", "#dcfce7")]:
            tk.Label(hero, text="  ✓  " + label, bg=color, fg="#26346b", font=(self.font_family, 9, "bold"), padx=10, pady=8).pack(anchor="w", pady=5)
        form = self.card(shell, 26)
        form.pack(side="left", fill="y", ipadx=12)
        ttk.Label(form, text="Sign in", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(form, text="Access your secure workspace", style="CardText.TLabel").pack(anchor="w", pady=(4, 14))
        email, _ = self.field(form, "Email / account identifier")
        password, _ = self.field(form, "Account password", secret=True)
        def login():
            e, p = email.get(), password.get(); password.set("")
            self.run(lambda: self.service.login(e, p), lambda exists: self.show_unlock() if exists else self.show_setup())
        def register():
            e, p = email.get(), password.get(); password.set("")
            self.run(lambda: self.service.register(e, p), lambda _: messagebox.showinfo("Account created", "Your account is ready. Sign in with your account password.", parent=self))
        self.action_button(form, "Sign in securely  →", login, True).pack(fill="x", pady=(20, 9))
        self.action_button(form, "Create a new account", register).pack(fill="x")
        ttk.Label(form, text="Use dummy credentials for your academic demo.\nNo server-side master-passphrase recovery.", style="CardText.TLabel", wraplength=260).pack(anchor="w", pady=(20, 0))

    def show_setup(self):
        self.clear(
            "Create your encrypted vault",
            "Choose a distinct, long master passphrase. Losing it means losing access to your vault.",
        )
        form = self.card(self.body, 26); form.pack(fill="x", padx=(0, 260))
        ttk.Label(form, text="Create your private key", style="CardTitle.TLabel").pack(anchor="w")
        first, _ = self.field(form, "Master passphrase (12–256 characters)", secret=True)
        second, _ = self.field(form, "Confirm master passphrase", secret=True)

        def create():
            p, confirm = first.get(), second.get()
            if p != confirm:
                return messagebox.showerror(
                    "Passphrases differ", "Enter the same passphrase twice.", parent=self
                )
            first.set("")
            second.set("")
            self.run(lambda: self.service.setup(p), lambda _: self.show_records())

        ttk.Button(self.body, text="Create encrypted vault  →", style="Accent.TButton", command=create).pack(
            anchor="w", pady=20
        )
        ttk.Button(self.body, text="Log out", command=self.logout).pack(anchor="w")

    def show_unlock(self):
        self.clear(
            "Unlock your vault", "The master passphrase stays on this computer. It is never sent to the API."
        )
        form = self.card(self.body, 26); form.pack(fill="x", padx=(0, 300))
        ttk.Label(form, text="Vault authentication", style="CardTitle.TLabel").pack(anchor="w")
        password, _ = self.field(form, "Master passphrase", secret=True)

        def unlock():
            p = password.get()
            password.set("")
            self.run(lambda: self.service.unlock(p), lambda _: self.show_records())

        ttk.Button(self.body, text="Unlock vault  →", style="Accent.TButton", command=unlock).pack(anchor="w", pady=20)
        ttk.Button(self.body, text="Log out", command=self.logout).pack(anchor="w")

    def show_records(self):
        self.clear(
            "Your vault",
            "Search happens locally after authenticated decryption. Titles, URLs and all secret fields are encrypted together.",
        )
        toolbar = ttk.Frame(self.body)
        toolbar.pack(fill="x")
        for text, command in [
            ("Add record", lambda: self.show_editor()),
            ("Edit", self.edit_selected),
            ("Delete", self.delete_selected),
            ("Refresh", lambda: self.run(self.service.refresh, lambda _: self.show_records())),
            ("Lock", self.lock_vault),
            ("Log out", self.logout),
        ]:
            ttk.Button(toolbar, text=text, command=command).pack(side="left", padx=(0, 6))
        search, _ = self.field(self.body, "Local search")
        tree = ttk.Treeview(self.body, columns=("title", "username", "url"), show="headings", height=10)
        self.tree = tree
        for name, width in [("title", 260), ("username", 220), ("url", 300)]:
            tree.heading(name, text=name.title())
            tree.column(name, width=width)
        tree.pack(fill="both", expand=True, pady=10)
        tree.bind("<Double-1>", lambda _: self.edit_selected())

        def filter_records(*_):
            tree.delete(*tree.get_children())
            needle = search.get().casefold()
            for rid, (_, plain) in self.service.records.items():
                if needle in "\n".join([plain.title, plain.username, plain.url, plain.notes]).casefold():
                    tree.insert("", "end", iid=rid, values=(plain.title, plain.username, plain.url))

        search.trace_add("write", filter_records)
        filter_records()
        footer = ttk.Frame(self.body)
        footer.pack(fill="x")
        for text, command in [
            ("Change master passphrase", self.show_master_change),
            ("Change account password", self.show_password_change),
            ("Security information", self.show_security),
            ("Cyber Attack Lab", self.show_attack_lab),
        ]:
            ttk.Button(footer, text=text, command=command).pack(side="left", padx=(0, 8))

    def selected(self):
        values = self.tree.selection()
        return values[0] if values else None

    def edit_selected(self):
        if self.selected():
            self.show_editor(self.selected())

    def delete_selected(self):
        rid = self.selected()
        if rid and messagebox.askyesno(
            "Delete record", "Delete this record from the active vault?", parent=self
        ):
            self.run(lambda: self.service.delete_record(rid), lambda _: self.show_records())

    def show_editor(self, record_id=None):
        plain = self.service.records[record_id][1] if record_id else PlainRecord(title="New credential")
        self.clear(
            "Edit record" if record_id else "Add a record",
            "Changes are encrypted locally before synchronization.",
        )
        variables = {}
        for name in ("title", "username", "password", "url"):
            variable, entry = self.field(
                self.body, name.title(), getattr(plain, name), secret=(name == "password")
            )
            variables[name] = variable
            if name == "password":
                revealed = tk.BooleanVar(value=False)
                ttk.Checkbutton(
                    self.body,
                    text="Reveal secret",
                    variable=revealed,
                    command=lambda e=entry, v=revealed: e.configure(show="" if v.get() else "*"),
                ).pack(anchor="w")
        ttk.Label(self.body, text="Notes").pack(anchor="w", pady=(10, 2))
        notes = tk.Text(self.body, height=5, font=(self.font_family, 11), wrap="word")
        notes.insert("1.0", plain.notes)
        notes.pack(fill="both", expand=True)

        def save():
            try:
                data = PlainRecord(
                    **{k: v.get() for k, v in variables.items()}, notes=notes.get("1.0", "end-1c")
                )
            except ValidationError:
                return messagebox.showerror(
                    "Invalid record", "Check field lengths; a title is required.", parent=self
                )
            self.run(lambda: self.service.save_record(data, record_id), lambda _: self.show_records())

        row = ttk.Frame(self.body)
        row.pack(fill="x", pady=10)
        ttk.Button(row, text="Encrypt and save", command=save).pack(side="left")
        ttk.Button(row, text="Cancel", command=self.show_records).pack(side="left", padx=8)
        ttk.Button(row, text="Lock", command=self.lock_vault).pack(side="right")

    def change_form(self, title, account=False):
        self.clear(
            title, "Account passwords and master passphrases have separate roles. Use different values."
        )
        old, _ = self.field(
            self.body, "Current password" if account else "Current master passphrase", secret=True
        )
        new, _ = self.field(self.body, "New value (12–256 characters)", secret=True)
        confirm, _ = self.field(self.body, "Confirm new value", secret=True)

        def change():
            o, n = old.get(), new.get()
            if n != confirm.get():
                return messagebox.showerror("Values differ", "Enter matching new values.", parent=self)
            old.set("")
            new.set("")
            confirm.set("")
            method = self.service.change_account_password if account else self.service.change_master
            self.run(lambda: method(o, n), lambda _: self.show_login() if account else self.show_records())

        ttk.Button(
            self.body, text="Change and sign in again" if account else "Rewrap vault key", command=change
        ).pack(anchor="w", pady=15)
        ttk.Button(self.body, text="Cancel", command=self.show_records).pack(anchor="w")
        if not account:
            ttk.Label(
                self.body,
                text="An old stolen envelope can still be attacked using guesses of the old passphrase.",
                wraplength=800,
            ).pack(anchor="w", pady=16)

    def show_master_change(self):
        self.change_form("Change master passphrase")

    def show_password_change(self):
        self.change_form("Change account password", account=True)

    def show_security(self):
        vault = self.service.vault
        tls = self.service.api.tls_info
        self.clear("Security information")
        info = [
            f"Server: {self.service.api.base_url}",
            f"Account ID: {self.service.user_id}",
            f"Vault ID: {vault.id}",
            "Record encryption: AES-256-GCM; 96-bit random nonce; 128-bit tag",
            f"Wrapping KDF: PBKDF2-HMAC-SHA256 / {vault.envelope.kdf_iterations:,} iterations",
            f"Envelope revision: {vault.envelope.envelope_revision}; key version: {vault.envelope.key_version}",
            f"Inactivity timeout: {self.timeout} seconds",
            f"Last observed TLS: {tls['protocol']} / {tls['cipher']}"
            if tls
            else "TLS parameters: not yet observed",
            "ECDHE group: verify with scripts/tls_probe.py (not exposed by Python SSL).",
            "Client/OS must be trusted. Offline guesses, metadata leakage and full-server rollback remain risks.",
            "Python does not guarantee secure memory erasure. Local deployment is a simulated cloud.",
        ]
        for line in info:
            ttk.Label(self.body, text=line, wraplength=860).pack(anchor="w", pady=6)
        ttk.Button(self.body, text="Back to vault", command=self.show_records).pack(anchor="w", pady=15)

    def show_attack_lab(self):
        self.clear(
            "Cyber Attack Simulation Lab",
            "Explore how common attacks work, execute safe backend demonstrations, and inspect the exact controls VaultShield uses to defend your data."
        )

        scenarios = [
            ("Man-in-the-Middle (MITM)", "mitm", "🛡", "#5b4be7",
             "An intermediary attempts to impersonate the server or alter traffic.",
             "TLS 1.3 · trusted CA · hostname verification"),
            ("Replay attack", "replay", "↻", "#087eae",
             "A previously valid request is submitted again after its context changes.",
             "Session expiry · revocation · revision checks"),
            ("Password guessing / brute force", "bruteforce", "🔐", "#b45309",
             "Repeated password guesses test whether online attempts are limited.",
             "PBKDF2 · account/peer rate limiting"),
            ("Ciphertext tampering", "tamper", "⚡", "#be3455",
             "Encrypted bytes are modified to test the AES-GCM authentication tag.",
             "AES-256-GCM · authentication tag"),
        ]

        hero = tk.Frame(self.body, bg="#171f4b", padx=22, pady=18,
                        highlightthickness=1, highlightbackground="#6c62ed")
        hero.pack(fill="x", pady=(0, 16))
        tk.Label(hero, text="DEFEND • DETECT • UNDERSTAND", bg="#171f4b", fg="#b9b5ff",
                 font=(self.font_family, 9, "bold")).pack(anchor="w")
        tk.Label(hero, text="Choose an attack to investigate", bg="#171f4b", fg="#ffffff",
                 font=(self.font_family, 20, "bold")).pack(anchor="w", pady=(5, 3))
        tk.Label(hero, text="Each run is sent to your authenticated VaultShield API and recorded in the account-scoped audit log.",
                 bg="#171f4b", fg="#d4dcff", font=(self.font_family, 9),
                 wraplength=1250, justify="left").pack(anchor="w")

        selected_kind = {"value": "mitm"}
        tiles = tk.Frame(self.body, bg=self.palette["page"])
        tiles.pack(fill="x", pady=(0, 12))
        tiles.grid_columnconfigure(0, weight=1, uniform="attack")
        tiles.grid_columnconfigure(1, weight=1, uniform="attack")
        tile_widgets = {}

        report_card = self.card(self.body, 16)
        report_head = tk.Frame(report_card, bg="#ffffff")
        report_head.pack(fill="x")
        tk.Label(report_head, text="SIMULATION WALKTHROUGH", bg="#ffffff", fg="#4f46cf",
                 font=(self.font_family, 9, "bold")).pack(anchor="w")
        report_title = tk.Label(report_head, text="Ready when you are", bg="#ffffff", fg="#11183f",
                                font=(self.font_family, 15, "bold"))
        report_title.pack(anchor="w", pady=(3, 2))
        report_status = tk.Label(report_head, text="Select an attack card above, then run its backend simulation.",
                                 bg="#ffffff", fg="#536184", font=(self.font_family, 9))
        report_status.pack(anchor="w", pady=(0, 10))

        out_wrap = tk.Frame(report_card, bg="#111735", padx=2, pady=2)
        out_wrap.pack(fill="both", expand=True)
        scrollbar = ttk.Scrollbar(out_wrap)
        output = tk.Text(
            out_wrap, height=12, wrap="word", relief="flat", bg="#111a3a", fg="#e8edff",
            padx=18, pady=15, font=(self.font_family, 10), spacing1=3, spacing3=5,
            yscrollcommand=scrollbar.set, state="disabled", borderwidth=0,
            insertbackground="#ffffff"
        )
        scrollbar.configure(command=output.yview)
        scrollbar.pack(side="right", fill="y")
        output.pack(side="left", fill="both", expand=True)
        output.tag_configure("section", font=(self.font_family, 10, "bold"),
                             foreground="#a99fff", spacing1=13, spacing3=5)
        output.tag_configure("step", foreground="#e0e7ff", lmargin1=12, lmargin2=30, spacing1=3)
        output.tag_configure("good", foreground="#6ee7b7", font=(self.font_family, 10, "bold"))
        output.tag_configure("muted", foreground="#a5b4d6")
        output.tag_configure("body", foreground="#e8edff")

        def write_report(data):
            output.configure(state="normal")
            output.delete("1.0", "end")

            def section(title, content=None):
                output.insert("end", title.upper() + "\n", "section")
                if content:
                    output.insert("end", content.strip() + "\n\n", "body")

            section(data.get("title", "Simulation result"))
            output.insert("end", "DEFENCE RESULT: " + data.get("outcome", "COMPLETED") + "\n", "good")
            output.insert("end", data.get("summary", "") + "\n\n", "body")
            section("01 · What does this attack mean?", data.get("meaning", "No definition supplied."))
            section("02 · How can an attacker do it?")
            for i, item in enumerate(data.get("how_it_happens", []), 1):
                output.insert("end", f"   {i}. {item}\n", "step")
            output.insert("end", "\n")
            section("03 · What happened during this simulation?")
            for i, item in enumerate(data.get("steps", []), 1):
                output.insert("end", f"   STEP {i:02d}  {item}\n", "step")
            output.insert("end", "\n")
            section("04 · How does VaultShield protect itself?")
            for item in data.get("defence_details", []):
                output.insert("end", f"   ✓  {item}\n", "good")
            output.insert("end", "\n")
            section("Main security control", data.get("control", "Not specified"))
            section("05 · Key takeaway", data.get("takeaway", "Review the defence controls above."))
            section("Backend execution evidence")
            output.insert("end", f"   Server audit log: {'RECORDED' if data.get('server_recorded') else 'NOT CONFIRMED'}\n", "good")
            output.insert("end", f"   Mode: {data.get('mode', 'SAFE LOCAL SIMULATION')}\n", "muted")
            output.insert("end", f"   Simulation ID: {data.get('simulation_id', '—')}\n", "muted")
            output.configure(state="disabled")
            output.yview_moveto(0)

        def run_selected(kind, title):
            selected_kind["value"] = kind
            report_title.configure(text=title)
            report_status.configure(text="Sending authenticated request to the VaultShield backend…")
            output.configure(state="normal")
            output.delete("1.0", "end")
            output.insert("end", "Connecting to the local authenticated API…\n\n", "muted")
            output.insert("end", "The server will execute the selected teaching scenario, return its explanation and defence analysis, and write an audit event.\n", "body")
            output.configure(state="disabled")
            self.run(
                lambda: self.service.api.run_simulation(kind),
                lambda data: (
                    report_status.configure(text="Backend execution complete · Detailed explanation and server evidence below."),
                    write_report(data)
                )
            )

        def select_card(kind, title):
            selected_kind["value"] = kind
            for k, (frame, button) in tile_widgets.items():
                is_selected = k == kind
                frame.configure(highlightbackground="#6554e8" if is_selected else "#cbd2ff",
                                highlightthickness=3 if is_selected else 1)
                button.configure(style="Accent.TButton" if is_selected else "TButton")
            report_title.configure(text=title)
            report_status.configure(text="Selected. Click “Run selected simulation” to execute it on the backend.")

        for idx, (title, kind, symbol, color, description, controls) in enumerate(scenarios):
            r, c = divmod(idx, 2)
            card = tk.Frame(tiles, bg="#ffffff", padx=16, pady=13,
                            highlightthickness=1, highlightbackground="#cbd2ff")
            card.grid(row=r, column=c, sticky="nsew", padx=(0, 8) if c == 0 else (8, 0),
                      pady=(0, 10))
            top = tk.Frame(card, bg="#ffffff")
            top.pack(fill="x")
            icon = tk.Label(top, text=symbol, bg=color, fg="#ffffff",
                            font=(self.font_family, 14, "bold"), width=3, height=1)
            icon.pack(side="left", padx=(0, 10))
            tk.Label(top, text=title, bg="#ffffff", fg="#172554",
                     font=(self.font_family, 11, "bold")).pack(side="left", anchor="w")
            tk.Label(card, text=description, bg="#ffffff", fg="#536184",
                     font=(self.font_family, 9), wraplength=560, justify="left").pack(anchor="w", pady=(10, 6))
            tk.Label(card, text="DEFENCE  ·  " + controls, bg="#ffffff", fg=color,
                     font=(self.font_family, 8, "bold"), wraplength=560,
                     justify="left").pack(anchor="w", pady=(0, 10))
            button = self.action_button(card, "Select this attack  →",
                                        lambda k=kind, t=title: select_card(k, t))
            button.pack(anchor="w")
            for widget in (card, top, icon):
                widget.bind("<Enter>", lambda _e, f=card: f.configure(highlightbackground="#8175ff", highlightthickness=2))
                widget.bind("<Leave>", lambda _e, f=card, k=kind: f.configure(
                    highlightbackground="#6554e8" if selected_kind["value"] == k else "#cbd2ff",
                    highlightthickness=3 if selected_kind["value"] == k else 1))
            tile_widgets[kind] = (card, button)

        select_card("mitm", "Man-in-the-Middle (MITM)")

        action_bar = tk.Frame(self.body, bg=self.palette["page"])
        action_bar.pack(fill="x", pady=(0, 12))
        self.action_button(action_bar, "▶  Run selected simulation",
                           lambda: run_selected(selected_kind["value"],
                               next(x[0] for x in scenarios if x[1] == selected_kind["value"])),
                           True).pack(side="left")
        self.action_button(action_bar, "View server audit history",
                           lambda: self.run(self.service.api.simulation_history, show_history)
                           ).pack(side="left", padx=10)
        self.action_button(action_bar, "← Back to vault", self.show_records).pack(side="right")

        report_card.pack(fill="both", expand=True, pady=(0, 4))

        def show_history(rows):
            data = {
                "title": "Server audit history",
                "outcome": f"{len(rows)} events",
                "summary": "These events were retrieved from the authenticated VaultShield backend.",
                "meaning": "The audit history provides evidence that simulation requests reached the server and were recorded for this account.",
                "how_it_happens": [
                    "The desktop client requests the authenticated simulation-history endpoint.",
                    "The server validates the session and filters events to the signed-in account.",
                    "The server returns the latest recorded simulation events."
                ],
                "steps": [
                    f"{r['event']} · {r['result']} · {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['time']))}"
                    for r in rows
                ] or ["No simulations have been recorded yet."],
                "defence_details": [
                    "History is scoped to the authenticated account.",
                    "Audit entries contain event metadata, not vault plaintext or master passphrases."
                ],
                "control": "Authenticated API access + account-scoped audit storage",
                "takeaway": "A backend audit event confirms that the server handled and recorded the selected demonstration.",
                "server_recorded": True,
                "mode": "AUDIT HISTORY"
            }
            write_report(data)
            report_title.configure(text="Server audit history")
            report_status.configure(text="Retrieved from the authenticated server audit log.")

    def lock_vault(self):
        self.service.lock()
        self.show_unlock()

    def logout(self):
        if self.busy:
            return
        self.service.lock()
        self.clear("Signing out…")

        def done(_):
            self.show_login()

        self.run(self.service.logout, done)

    def close(self):
        self.service.lock()
        # A request may already be in flight; do not race it with httpx.close().
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.destroy()


def main():
    parser = argparse.ArgumentParser(description="VaultShield desktop client")
    parser.add_argument("--server", default="https://localhost:8443")
    parser.add_argument("--ca", help="Trusted local CA certificate PEM")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    if not 30 <= args.timeout <= 3600:
        parser.error("--timeout must be 30–3600 seconds")
    api = VaultAPI(args.server, args.ca)
    try:
        VaultWindow(VaultService(api), args.timeout).mainloop()
    finally:
        # Executor tasks use finite timeouts; interpreter waits for them at exit.
        pass


if __name__ == "__main__":
    main()
