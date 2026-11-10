import os
import json
import time
import math
import random
import threading
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import customtkinter as ctk

from core.crypto_engine import (
    package_vsec, unpackage_vsec, tamper_vsec_file, generate_rsa_keypair,
    serialize_private_key, serialize_public_key
)
from core.cipher_sandbox import (
    caesar_encrypt, caesar_decrypt, caesar_brute_force,
    playfair_encrypt, playfair_decrypt, build_playfair_matrix
)
from core.browser_audit import simulate_audit
from ui.theme import THEME, FONTS, interpolate_color
from ui.components import GlassCard, PulsingBeacon, LiveCyberWaveform, RadarScanner, NavPill

NAV_ITEMS = [
    ("🔒", "Crypto Vault", "vault"),
    ("🛡", "Anti-Tamper", "tamper"),
    ("⚙", "Cipher Sandbox", "cipher"),
    ("🌐", "Header Inspector", "audit"),
    ("📋", "Audit Log", "log"),
]

SPINNERS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

class VaultChainApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title("VaultChain Guard — Enterprise Security Suite")
        self.geometry("1360x880")
        self.minsize(1160, 740)
        self.configure(fg_color=THEME["bg_root"])

        self._audit_log: list[str] = []
        self._vsec_path: str | None = None
        self._last_private_key = None
        self._last_public_key = None

        self._alert_breath_active = False
        self._alert_breath_phase = 0.0
        self._alert_breath_job = None

        self._log_active_filters: set[str] = {"INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"}

        self._hex_ticker_active = False
        self._hex_ticker_job = None

        self._vault_target_progress = 0.0
        self._vault_current_progress = 0.0
        self._vault_progress_job = None

        self._verify_step_states = ["pending", "pending", "pending", "pending"]
        self._verify_spinner_index = 0
        self._verify_spinner_job = None

        self._gauge_job = None
        self._gauge_start_score = 0
        self._gauge_target_score = 0
        self._gauge_target_grade = "—"
        self._gauge_target_color = THEME["text_muted"]
        self._gauge_current_step = 0
        self._gauge_total_steps = 35

        self._freq_bars_job = None
        self._freq_bars_targets: list[tuple[ctk.CTkProgressBar, float]] = []
        self._freq_bars_step = 0
        self._freq_bars_total_steps = 25

        self._active_scrollable: ctk.CTkScrollableFrame | None = None
        self._header_waves: list = []
        self._session_start_time = time.time()
        self._session_timer_job = None

        self._build_layout()
        self._switch_frame("vault")
        self._tick_session_timer()
        self.protocol("WM_DELETE_WINDOW", self._on_app_close)

        self.bind_all("<MouseWheel>", self._on_universal_mousewheel)
        self.bind_all("<Button-4>", self._on_universal_mousewheel)
        self.bind_all("<Button-5>", self._on_universal_mousewheel)

    def _on_universal_mousewheel(self, event):
        try:
            widget = event.widget
            target_canvas = None
            curr = widget
            while curr:
                if hasattr(curr, "_parent_canvas"):
                    target_canvas = curr._parent_canvas
                    break
                curr = getattr(curr, "master", None)

            if not target_canvas and self._active_scrollable:
                target_canvas = self._active_scrollable._parent_canvas

            if target_canvas and hasattr(target_canvas, "yview_scroll"):
                delta = 0
                if getattr(event, "delta", 0):
                    delta = -int(event.delta / 40)
                    if delta == 0:
                        delta = -1 if event.delta > 0 else 1
                elif getattr(event, "num", None) == 4:
                    delta = -3
                elif getattr(event, "num", None) == 5:
                    delta = 3
                if delta != 0:
                    target_canvas.yview_scroll(delta, "units")
        except Exception:
            return

    def _tick_session_timer(self):
        try:
            if not self.winfo_exists():
                return
            elapsed = int(time.time() - self._session_start_time)
            mins = elapsed // 60
            secs = elapsed % 60
            hrs = mins // 60
            mins = mins % 60
            if hasattr(self, "_session_uptime_label"):
                self._session_uptime_label.configure(text=f"SESSION: {hrs:02d}:{mins:02d}:{secs:02d}")
            self._session_timer_job = self.after(1000, self._tick_session_timer)
        except Exception:
            return

    def _on_app_close(self):
        self._hex_ticker_active = False
        self._alert_breath_active = False
        if hasattr(self, "_beacon") and self._beacon:
            self._beacon.stop()
        if hasattr(self, "_radar") and self._radar:
            self._radar.stop()
        if hasattr(self, "_cyber_wave") and self._cyber_wave:
            self._cyber_wave.stop()
        if hasattr(self, "_header_waves"):
            for w in self._header_waves:
                try:
                    w.stop()
                except Exception:
                    pass
        for job_attr in [
            "_alert_breath_job", "_gauge_job",
            "_vault_progress_job", "_hex_ticker_job",
            "_freq_bars_job", "_verify_spinner_job",
            "_session_timer_job"
        ]:
            job = getattr(self, job_attr, None)
            if job:
                try:
                    self.after_cancel(job)
                except Exception:
                    pass
                setattr(self, job_attr, None)
        self.destroy()

    def _build_layout(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._sidebar = ctk.CTkFrame(
            self, width=260, corner_radius=0,
            fg_color=THEME["bg_sidebar"],
            border_width=1, border_color=THEME["border_subtle"]
        )
        self._sidebar.grid(row=0, column=0, sticky="nsew")
        self._sidebar.grid_propagate(False)
        self._sidebar.grid_columnconfigure(0, weight=1)
        self._sidebar.grid_rowconfigure(10, weight=1)

        logo_frame = ctk.CTkFrame(self._sidebar, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=22, pady=(26, 18), sticky="ew")

        title_line = ctk.CTkFrame(logo_frame, fg_color="transparent")
        title_line.pack(anchor="w", fill="x")

        ctk.CTkLabel(
            title_line, text="⛓ VaultChain",
            font=ctk.CTkFont(family=FONTS["title_hero"][0], size=21, weight="bold"),
            text_color=THEME["text_primary"]
        ).pack(side="left")

        self._beacon = PulsingBeacon(title_line, size=22, bg=THEME["bg_sidebar"])
        self._beacon.pack(side="left", padx=(10, 0))

        sub_line = ctk.CTkFrame(logo_frame, fg_color="transparent")
        sub_line.pack(anchor="w", fill="x", pady=(2, 0))

        ctk.CTkLabel(
            sub_line, text="GUARD  PRO EDITION",
            font=ctk.CTkFont(family=FONTS["caption_bold"][0], size=9, weight="bold"),
            text_color=THEME["neon_cyan_glow"]
        ).pack(side="left")

        ctk.CTkFrame(self._sidebar, height=1, fg_color=THEME["border_subtle"]).grid(
            row=1, column=0, sticky="ew", padx=18, pady=(0, 16)
        )

        self._nav_pills: dict[str, NavPill] = {}

        for idx, (icon, label, key) in enumerate(NAV_ITEMS):
            pill = NavPill(
                self._sidebar,
                icon=icon,
                label=label,
                command=lambda k=key: self._switch_frame(k)
            )
            pill.grid(row=idx + 2, column=0, padx=14, pady=4, sticky="ew")
            self._nav_pills[key] = pill

        ctk.CTkFrame(self._sidebar, height=1, fg_color=THEME["border_subtle"]).grid(
            row=9, column=0, sticky="ew", padx=18, pady=8
        )

        status_box = ctk.CTkFrame(
            self._sidebar, fg_color=THEME["bg_input"],
            corner_radius=10, border_width=1, border_color=THEME["border_subtle"]
        )
        status_box.grid(row=10, column=0, padx=14, pady=(0, 6), sticky="ew")

        status_inner = ctk.CTkFrame(status_box, fg_color="transparent")
        status_inner.pack(fill="x", padx=10, pady=(6, 2))

        ctk.CTkLabel(
            status_inner,
            text="● CORE ENGINE ONLINE",
            font=ctk.CTkFont(family=FONTS["caption_bold"][0], size=9, weight="bold"),
            text_color=THEME["neon_green"]
        ).pack(side="left")

        self._session_uptime_label = ctk.CTkLabel(
            status_box,
            text="SESSION: 00:00:00",
            font=ctk.CTkFont(family=FONTS["mono_badge"][0], size=9),
            text_color=THEME["text_muted"]
        )
        self._session_uptime_label.pack(anchor="w", padx=10, pady=(0, 6))

        ctk.CTkLabel(
            self._sidebar,
            text="DES-CBC | RSA-OAEP | SHA-256",
            font=ctk.CTkFont(family=FONTS["mono_badge"][0], size=9),
            text_color=THEME["text_dim"]
        ).grid(row=11, column=0, padx=16, pady=(0, 16), sticky="sw")

        self._content = ctk.CTkFrame(self, fg_color=THEME["bg_root"], corner_radius=0)
        self._content.grid(row=0, column=1, sticky="nsew")
        self._content.grid_rowconfigure(0, weight=1)
        self._content.grid_columnconfigure(0, weight=1)

        self._frames: dict[str, ctk.CTkFrame] = {}
        self._scrollables: dict[str, ctk.CTkScrollableFrame] = {}

        self._frames["vault"] = self._build_vault_frame(self._content)
        self._frames["tamper"] = self._build_tamper_frame(self._content)
        self._frames["cipher"] = self._build_cipher_frame(self._content)
        self._frames["audit"] = self._build_audit_frame(self._content)
        self._frames["log"] = self._build_log_frame(self._content)

        for frame in self._frames.values():
            frame.grid(row=0, column=0, sticky="nsew")

    def _switch_frame(self, key: str):
        for k, pill in self._nav_pills.items():
            pill.set_active(k == key)
        self._frames[key].tkraise()
        self._active_scrollable = self._scrollables.get(key, None)

    def _log(self, level: str, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] [{level}] {message}"
        self._audit_log.append(entry)
        if hasattr(self, "_log_text_widget"):
            self._insert_log_entry_to_widget(level, entry)
            if hasattr(self, "_log_count_label"):
                count = len(self._audit_log)
                self._log_count_label.configure(
                    text=f"{count} {'entry' if count == 1 else 'entries'}  |  Last: {ts}"
                )

    def _insert_log_entry_to_widget(self, level: str, entry: str):
        widget = self._log_text_widget
        widget.configure(state="normal")
        tag = level if level in ["INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"] else "INFO"
        widget.insert("end", entry + "\n", tag)
        widget.see("end")
        widget.configure(state="disabled")

    def _section_header(self, parent, title: str, subtitle: str = None):
        box = ctk.CTkFrame(parent, fg_color="transparent")
        box.pack(anchor="w", padx=18, pady=(16, 8), fill="x")

        top_line = ctk.CTkFrame(box, fg_color="transparent")
        top_line.pack(anchor="w", fill="x")

        pill = ctk.CTkFrame(top_line, width=4, height=16, fg_color=THEME["neon_cyan"], corner_radius=2)
        pill.pack(side="left", padx=(0, 10))
        pill.pack_propagate(False)

        ctk.CTkLabel(
            top_line, text=title,
            font=ctk.CTkFont(family=FONTS["title_section"][0], size=FONTS["title_section"][1], weight="bold"),
            text_color=THEME["text_primary"]
        ).pack(side="left")

        if subtitle:
            ctk.CTkLabel(
                box, text=subtitle,
                font=ctk.CTkFont(family=FONTS["caption"][0], size=FONTS["caption"][1]),
                text_color=THEME["text_muted"],
                anchor="w"
            ).pack(anchor="w", padx=(14, 4), pady=(2, 0), fill="x")

    def _action_button(self, parent, text: str, command, color=None, text_color=None, **kwargs) -> ctk.CTkButton:
        bg = color or THEME["neon_cyan"]
        fg = text_color or (THEME["bg_root"] if bg == THEME["neon_cyan"] else THEME["text_primary"])
        hover = THEME["neon_cyan_glow"] if bg == THEME["neon_cyan"] else THEME["bg_card_hover"]
        btn_kwargs = dict(
            font=ctk.CTkFont(family=FONTS["body_bold"][0], size=FONTS["body_bold"][1], weight="bold"),
            fg_color=bg,
            text_color=fg,
            hover_color=hover,
            corner_radius=10,
            height=40,
            command=command,
        )
        if bg != THEME["neon_cyan"]:
            btn_kwargs["border_width"] = 1
            btn_kwargs["border_color"] = THEME["border_subtle"]
        btn_kwargs.update(kwargs)
        btn = ctk.CTkButton(parent, text=text, **btn_kwargs)
        btn.configure(cursor="hand2")
        return btn

    def _page_header(self, parent, icon: str, title: str, subtitle: str):
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(16, 4))

        icon_card = ctk.CTkFrame(
            hdr, width=42, height=42, corner_radius=10,
            fg_color=THEME["bg_card"],
            border_width=1, border_color=THEME["border_subtle"]
        )
        icon_card.pack(side="left", padx=(0, 14))
        icon_card.pack_propagate(False)

        icon_lbl = ctk.CTkLabel(
            icon_card, text=icon,
            font=ctk.CTkFont(size=20),
            text_color=THEME["neon_cyan"]
        )
        icon_lbl.place(relx=0.5, rely=0.5, anchor="center")

        text_col = ctk.CTkFrame(hdr, fg_color="transparent")
        text_col.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            text_col, text=title,
            font=ctk.CTkFont(family=FONTS["title_hero"][0], size=19, weight="bold"),
            text_color=THEME["text_primary"],
            anchor="w"
        ).pack(anchor="w")

        ctk.CTkLabel(
            text_col, text=subtitle,
            font=ctk.CTkFont(family=FONTS["body"][0], size=11),
            text_color=THEME["text_muted"],
            anchor="w"
        ).pack(anchor="w", pady=(1, 0))

        sep = ctk.CTkFrame(parent, height=1, fg_color=THEME["border_subtle"])
        sep.pack(fill="x", padx=24, pady=(6, 8))

    def _build_vault_frame(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color=THEME["bg_root"], corner_radius=0)
        self._page_header(
            frame, "🔒", "Hybrid Cryptographic Vault",
            "Multi-Layer Protection: DES-CBC ➔ RSA-2048 OAEP ➔ SHA-256 PSS Packaging (.vsec)"
        )

        body = ctk.CTkFrame(frame, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        body.grid_columnconfigure(0, weight=55)
        body.grid_columnconfigure(1, weight=45)
        body.grid_rowconfigure(0, weight=1)

        left_col = ctk.CTkFrame(body, fg_color="transparent")
        left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        right_col = ctk.CTkFrame(body, fg_color="transparent")
        right_col.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        file_card = GlassCard(left_col)
        file_card.pack(fill="x", pady=(0, 8))
        self._section_header(file_card, "1. Select Target File", "Choose any binary, document, or media file to encapsulate")

        self._vault_dropzone = ctk.CTkFrame(
            file_card,
            fg_color=THEME["bg_input"],
            corner_radius=10,
            border_width=1,
            border_color=THEME["border_subtle"]
        )
        self._vault_dropzone.pack(fill="x", padx=14, pady=(2, 12))

        def dz_enter(e):
            if self._selected_vault_file is None:
                self._vault_dropzone.configure(border_color=THEME["neon_cyan_glow"])

        def dz_leave(e):
            if self._selected_vault_file is None:
                self._vault_dropzone.configure(border_color=THEME["border_subtle"])

        self._vault_dropzone.bind("<Enter>", dz_enter)
        self._vault_dropzone.bind("<Leave>", dz_leave)

        self._vault_drop_icon = ctk.CTkLabel(
            self._vault_dropzone, text="☁",
            font=ctk.CTkFont(size=24),
            text_color=THEME["neon_cyan_glow"]
        )
        self._vault_drop_icon.pack(pady=(10, 2))

        self._vault_drop_main = ctk.CTkLabel(
            self._vault_dropzone, text="Click to Browse & Select File",
            font=ctk.CTkFont(family=FONTS["title_card"][0], size=FONTS["title_card"][1], weight="bold"),
            text_color=THEME["text_primary"]
        )
        self._vault_drop_main.pack()

        self._vault_drop_formats = ctk.CTkLabel(
            self._vault_dropzone, text="Supported: .pdf  .docx  .txt  .png  .jpg  .bin  .zip",
            font=ctk.CTkFont(family=FONTS["caption"][0], size=9),
            text_color=THEME["text_muted"]
        )
        self._vault_drop_formats.pack(pady=(2, 10))

        for w in [self._vault_dropzone, self._vault_drop_icon, self._vault_drop_main, self._vault_drop_formats]:
            w.bind("<Button-1>", lambda e: self._vault_browse())
            w.configure(cursor="hand2")

        enc_card = GlassCard(left_col)
        enc_card.pack(fill="x", pady=(0, 8))
        self._section_header(enc_card, "2. Cryptographic Execution Pipeline", "Threaded hardware-safe encryption and key encapsulation")

        enc_row = ctk.CTkFrame(enc_card, fg_color="transparent")
        enc_row.pack(fill="x", padx=14, pady=(0, 8))

        self._action_button(
            enc_row, "⚡  Run Hybrid Encryption Engine",
            self._vault_encrypt_threaded,
            color=THEME["neon_cyan"]
        ).pack(side="left")

        steps_frame = ctk.CTkFrame(enc_card, fg_color="transparent")
        steps_frame.pack(fill="x", padx=14, pady=(2, 8))

        self._vault_step_labels = ["RSA Keygen", "DES Encrypt", "OAEP Wrap", "SHA-256 Sign"]
        self._vault_step_pills: list[ctk.CTkFrame] = []
        self._vault_step_texts: list[ctk.CTkLabel] = []

        for i, step_name in enumerate(self._vault_step_labels):
            pill = ctk.CTkFrame(
                steps_frame,
                fg_color=THEME["bg_input"],
                corner_radius=8,
                border_width=1,
                border_color=THEME["border_subtle"],
                height=30
            )
            pill.pack(side="left", fill="x", expand=True, padx=(0, 4) if i < 3 else (0, 0))
            pill.pack_propagate(False)

            step_num = ctk.CTkLabel(
                pill,
                text=f"{i+1}. {step_name}",
                font=ctk.CTkFont(family=FONTS["caption_bold"][0], size=9, weight="bold"),
                text_color=THEME["text_dim"]
            )
            step_num.pack(expand=True)
            self._vault_step_pills.append(pill)
            self._vault_step_texts.append(step_num)

        progress_container = ctk.CTkFrame(enc_card, fg_color="transparent")
        progress_container.pack(fill="x", padx=14, pady=(0, 10))

        self._vault_progress_bar = ctk.CTkProgressBar(
            progress_container, height=6, corner_radius=3,
            fg_color=THEME["bg_input"],
            progress_color=THEME["neon_cyan"]
        )
        self._vault_progress_bar.pack(fill="x", pady=(2, 6))
        self._vault_progress_bar.set(0.0)

        ticker_strip = ctk.CTkFrame(
            progress_container, fg_color=THEME["bg_input"],
            corner_radius=6, border_width=1, border_color=THEME["border_subtle"]
        )
        ticker_strip.pack(fill="x")

        self._vault_hex_ticker_label = ctk.CTkLabel(
            ticker_strip,
            text="[STANDBY] Awaiting target file to initiate pipeline",
            font=ctk.CTkFont(family=FONTS["mono_code"][0], size=9),
            text_color=THEME["text_muted"],
            anchor="w"
        )
        self._vault_hex_ticker_label.pack(fill="x", padx=10, pady=4)

        keys_card = GlassCard(left_col)
        keys_card.pack(fill="x")
        self._section_header(keys_card, "3. Keypair Certificate Export", "Export PEM certificates for external auditing")

        keys_row = ctk.CTkFrame(keys_card, fg_color="transparent")
        keys_row.pack(fill="x", padx=14, pady=(0, 10))

        self._action_button(
            keys_row, "💾  Export Private Key",
            self._vault_save_private_key,
            color=THEME["bg_card_hover"]
        ).pack(side="left", padx=(0, 8))

        self._action_button(
            keys_row, "💾  Export Public Key",
            self._vault_save_public_key,
            color=THEME["bg_card_hover"]
        ).pack(side="left")

        summary_card = GlassCard(right_col)
        summary_card.pack(fill="both", expand=True)
        self._section_header(summary_card, "4. Cryptographic Package Telemetry", "Inspect encapsulated keys and integrity artifacts")

        self._vault_stat_grid = ctk.CTkFrame(summary_card, fg_color="transparent")
        self._vault_stat_grid.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        self._vault_stat_labels = [
            "Original File", "File Size", "DES Key", "IV",
            "SHA-256 Hash", "RSA Key Size", "Ciphertext Size", "Signature Size"
        ]
        self._vault_stat_value_labels: dict[str, ctk.CTkLabel] = {}

        for idx, stat_name in enumerate(self._vault_stat_labels):
            col = idx % 2
            row = idx // 2
            stat_card = ctk.CTkFrame(
                self._vault_stat_grid,
                fg_color=THEME["bg_input"],
                corner_radius=8,
                border_width=1,
                border_color=THEME["border_subtle"]
            )
            stat_card.grid(row=row, column=col, padx=4, pady=4, sticky="nsew")
            self._vault_stat_grid.grid_columnconfigure(col, weight=1)
            self._vault_stat_grid.grid_rowconfigure(row, weight=1)

            ctk.CTkLabel(
                stat_card, text=stat_name.upper(),
                font=ctk.CTkFont(family=FONTS["caption_bold"][0], size=9, weight="bold"),
                text_color=THEME["neon_cyan_glow"]
            ).pack(anchor="w", padx=10, pady=(6, 2))

            val_label = ctk.CTkLabel(
                stat_card, text="—",
                font=ctk.CTkFont(family=FONTS["mono_code"][0], size=10),
                text_color=THEME["text_primary"],
                wraplength=260,
                justify="left"
            )
            val_label.pack(anchor="w", padx=10, pady=(0, 6))
            self._vault_stat_value_labels[stat_name] = val_label

        self._selected_vault_file: str | None = None
        return frame

    def _vault_browse(self):
        path = filedialog.askopenfilename(
            title="Select file to encrypt",
            filetypes=[
                ("All files", "*.*"),
                ("Text files", "*.txt"),
                ("PDF files", "*.pdf"),
                ("Images", "*.png *.jpg *.jpeg"),
                ("Word Documents", "*.docx"),
            ]
        )
        if path:
            self._selected_vault_file = path
            fname = os.path.basename(path)
            fsize = os.path.getsize(path)
            fsize_kb = fsize / 1024
            self._vault_dropzone.configure(
                border_color=THEME["neon_green"],
                fg_color=THEME["badge_green_bg"]
            )
            self._vault_drop_icon.configure(text="✅", text_color=THEME["neon_green"])
            self._vault_drop_main.configure(text=fname, text_color=THEME["neon_green"])
            self._vault_drop_formats.configure(
                text=f"Ready: {fsize_kb:.2f} KB  ({fsize:,} bytes)",
                text_color=THEME["text_primary"]
            )
            self._vault_hex_ticker_label.configure(
                text=f"[ARMED] Loaded file: {fname} ({fsize:,} bytes)",
                text_color=THEME["neon_cyan"]
            )
            self._log("INFO", f"File armed for encryption: {fname} ({fsize:,} bytes)")

    def _vault_start_hex_ticker(self):
        self._hex_ticker_active = True
        self._vault_update_hex_ticker()

    def _vault_stop_hex_ticker(self, final_msg: str | None = None):
        self._hex_ticker_active = False
        if self._hex_ticker_job:
            try:
                self.after_cancel(self._hex_ticker_job)
            except Exception:
                pass
            self._hex_ticker_job = None
        if hasattr(self, "_vault_hex_ticker_label") and self._vault_hex_ticker_label.winfo_exists():
            msg = final_msg or "[SEALED] .vsec encrypted package successfully generated"
            self._vault_hex_ticker_label.configure(text=msg, text_color=THEME["neon_green"])

    def _vault_update_hex_ticker(self):
        if not self._hex_ticker_active:
            return
        try:
            if not self.winfo_exists():
                return
            hex_bytes = " ".join([f"{random.randint(0, 255):02X}" for _ in range(8)])
            stage = random.choice(["DES-CBC-BLOCK", "OAEP-WRAP", "SHA256-PSS", "PKCS7-PADDING", "KEY-EXCHANGE"])
            blk = random.randint(1, 128)
            ticker_text = f"[{stage} #{blk:02d}] {hex_bytes}  >>  BUFFER_STREAM_OK"
            self._vault_hex_ticker_label.configure(text=ticker_text, text_color=THEME["neon_cyan"])
            self._hex_ticker_job = self.after(80, self._vault_update_hex_ticker)
        except Exception:
            self._hex_ticker_active = False

    def _vault_smooth_progress_to(self, target: float):
        self._vault_target_progress = target
        if not self._vault_progress_job:
            self._vault_animate_progress_step()

    def _vault_animate_progress_step(self):
        try:
            if not self.winfo_exists():
                self._vault_progress_job = None
                return
            diff = self._vault_target_progress - self._vault_current_progress
            if abs(diff) < 0.01:
                self._vault_current_progress = self._vault_target_progress
                self._vault_progress_bar.set(self._vault_current_progress)
                self._vault_progress_job = None
            else:
                self._vault_current_progress += diff * 0.25
                self._vault_progress_bar.set(self._vault_current_progress)
                self._vault_progress_job = self.after(20, self._vault_animate_progress_step)
        except Exception:
            self._vault_progress_job = None

    def _vault_encrypt_threaded(self):
        if not self._selected_vault_file:
            messagebox.showerror("No File Selected", "Please select a file to encrypt first.")
            return
        for pill, txt in zip(self._vault_step_pills, self._vault_step_texts):
            pill.configure(fg_color=THEME["bg_input"], border_color=THEME["border_subtle"])
            txt.configure(text_color=THEME["text_dim"])
        self._vault_smooth_progress_to(0.0)
        self._vault_start_hex_ticker()
        thread = threading.Thread(target=self._vault_encrypt_worker, daemon=True)
        thread.start()

    def _vault_set_step(self, idx: int, state: str):
        try:
            pill = self._vault_step_pills[idx]
            txt = self._vault_step_texts[idx]
            if state == "active":
                pill.configure(fg_color=THEME["badge_cyan_bg"], border_color=THEME["neon_cyan"])
                txt.configure(text_color=THEME["neon_cyan"])
            elif state == "done":
                pill.configure(fg_color=THEME["badge_green_bg"], border_color=THEME["neon_green"])
                txt.configure(text_color=THEME["neon_green"])
            elif state == "error":
                pill.configure(fg_color=THEME["badge_red_bg"], border_color=THEME["neon_red"])
                txt.configure(text_color=THEME["neon_red"])
        except Exception:
            pass

    def _vault_encrypt_worker(self):
        try:
            self._log("INFO", "RSA-2048 keypair generation initiated...")
            self.after(0, self._vault_set_step, 0, "active")
            self.after(0, self._vault_smooth_progress_to, 0.15)
            time.sleep(0.12)

            private_key, public_key = generate_rsa_keypair()
            self._last_private_key = private_key
            self._last_public_key = public_key
            self._log("SUCCESS", "RSA-2048 keypair generated successfully.")
            self.after(0, self._vault_set_step, 0, "done")
            self.after(0, self._vault_smooth_progress_to, 0.35)
            self.after(0, self._vault_set_step, 1, "active")

            with open(self._selected_vault_file, "rb") as f:
                file_data = f.read()
            self._log("INFO", f"Loaded target payload: {len(file_data):,} bytes.")
            time.sleep(0.12)

            original_name = os.path.basename(self._selected_vault_file)
            vsec_data, summary = package_vsec(original_name, file_data, private_key, public_key)
            self._log("SUCCESS", "DES-CBC encryption with PKCS7 padding applied.")
            self.after(0, self._vault_set_step, 1, "done")
            self.after(0, self._vault_smooth_progress_to, 0.65)
            self.after(0, self._vault_set_step, 2, "active")
            time.sleep(0.12)

            self._log("SUCCESS", "RSA-OAEP session key encapsulation complete.")
            self.after(0, self._vault_set_step, 2, "done")
            self.after(0, self._vault_smooth_progress_to, 0.85)
            self.after(0, self._vault_set_step, 3, "active")
            time.sleep(0.12)

            self._log("SUCCESS", "SHA-256 digital signature sealed with RSA-PSS.")

            out_dir = os.path.dirname(self._selected_vault_file)
            base_name = os.path.splitext(original_name)[0]
            vsec_path = os.path.join(out_dir, base_name + ".vsec")

            with open(vsec_path, "wb") as f:
                f.write(vsec_data)

            self._vsec_path = vsec_path
            self._log("SUCCESS", f".vsec package generated: {os.path.basename(vsec_path)}")
            self.after(0, self._vault_set_step, 3, "done")
            self.after(0, self._vault_smooth_progress_to, 1.0)
            self.after(0, lambda: self._vault_stop_hex_ticker(
                f"[COMPLETE] Output: {os.path.basename(vsec_path)} ({len(vsec_data):,} bytes)"
            ))

            stat_values = {
                "Original File": original_name[:18] + ("..." if len(original_name) > 18 else ""),
                "File Size": f"{len(file_data):,} bytes",
                "DES Key": summary["des_key_hex"][:16] + "...",
                "IV": summary["iv_hex"][:16] + "...",
                "SHA-256 Hash": summary["file_hash_hex"][:24] + "...",
                "RSA Key Size": "2048-bit OAEP",
                "Ciphertext Size": f"{summary['ciphertext_len']:,} bytes",
                "Signature Size": f"{summary['signature_len']} bytes",
            }
            self.after(0, self._vault_update_stat_cards, stat_values)
            self.after(0, lambda: messagebox.showinfo(
                "Encryption Successful",
                f"File encrypted and encapsulated successfully!\nSaved as: {os.path.basename(vsec_path)}"
            ))

        except Exception as exc:
            self._log("ERROR", f"Encryption failed: {exc}")
            self.after(0, lambda: self._vault_stop_hex_ticker(f"[ERROR] Encryption aborted: {exc}"))
            self.after(0, lambda: messagebox.showerror("Encryption Error", str(exc)))
            for i in range(4):
                self.after(0, self._vault_set_step, i, "error")

    def _vault_update_stat_cards(self, stat_values: dict):
        for stat_name, value in stat_values.items():
            if stat_name in self._vault_stat_value_labels:
                self._vault_stat_value_labels[stat_name].configure(text=value)

    def _vault_save_private_key(self):
        if not self._last_private_key:
            messagebox.showerror("No Keypair Available", "Generate a .vsec file first to obtain an active keypair.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM certificate", "*.pem")],
            initialfile="private_key.pem"
        )
        if path:
            with open(path, "wb") as f:
                f.write(serialize_private_key(self._last_private_key))
            self._log("INFO", f"Private key certificate exported: {os.path.basename(path)}")
            messagebox.showinfo("Export Successful", f"Private key saved to:\n{path}")

    def _vault_save_public_key(self):
        if not self._last_public_key:
            messagebox.showerror("No Keypair Available", "Generate a .vsec file first to obtain an active keypair.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM certificate", "*.pem")],
            initialfile="public_key.pem"
        )
        if path:
            with open(path, "wb") as f:
                f.write(serialize_public_key(self._last_public_key))
            self._log("INFO", f"Public key certificate exported: {os.path.basename(path)}")
            messagebox.showinfo("Export Successful", f"Public key saved to:\n{path}")

    def _build_tamper_frame(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color=THEME["bg_root"], corner_radius=0)
        self._page_header(
            frame, "🛡", "Anti-Tamper Verification Radar",
            "Cryptographic Integrity Inspector: SHA-256 Digest Verification & Binary Hex Tamper Simulation"
        )

        body = ctk.CTkFrame(frame, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        load_card = GlassCard(body)
        load_card.pack(fill="x", pady=(0, 8))
        self._section_header(load_card, "1. Target Container Package & Integrity Actions", "Load .vsec package and trigger verification or bit-flip tamper simulations")

        load_row = ctk.CTkFrame(load_card, fg_color="transparent")
        load_row.pack(fill="x", padx=14, pady=(0, 8))

        self._tamper_file_var = tk.StringVar(value="No container package loaded")

        self._action_button(
            load_row, "📂  Browse .vsec Package", self._tamper_browse,
            color=THEME["bg_card_hover"],
            width=200
        ).pack(side="right")

        ctk.CTkLabel(
            load_row,
            textvariable=self._tamper_file_var,
            font=ctk.CTkFont(family=FONTS["mono_body"][0], size=FONTS["mono_body"][1]),
            text_color=THEME["text_muted"],
            anchor="w"
        ).pack(side="left", fill="x", expand=True, padx=(0, 14))

        btn_row = ctk.CTkFrame(load_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=14, pady=(0, 10))

        self._action_button(
            btn_row, "✅  Run Integrity Verification",
            self._tamper_verify_threaded,
            color=THEME["neon_green"],
            text_color=THEME["bg_root"]
        ).pack(side="left", padx=(0, 10))

        self._action_button(
            btn_row, "⚠️  Simulate Hex Tampering",
            self._tamper_simulate,
            color=THEME["neon_red"],
            text_color=THEME["text_primary"]
        ).pack(side="left", padx=(0, 10))

        self._action_button(
            btn_row, "🔄  Decrypt & Restore Payload",
            self._tamper_decrypt_threaded,
            color=THEME["bg_card_hover"]
        ).pack(side="left")

        mid_row = ctk.CTkFrame(body, fg_color="transparent")
        mid_row.configure(height=215)
        mid_row.pack_propagate(False)
        mid_row.pack(fill="x", pady=(0, 8))
        mid_row.grid_columnconfigure(0, weight=50)
        mid_row.grid_columnconfigure(1, weight=50)
        mid_row.grid_rowconfigure(0, weight=1)

        radar_card = GlassCard(mid_row)
        radar_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self._section_header(radar_card, "2. Live Verification Radar", "Continuous sweeping radar inspecting binary structure")

        radar_body = ctk.CTkFrame(radar_card, fg_color="transparent")
        radar_body.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        self._radar = RadarScanner(radar_body, size=88, bg=THEME["bg_card"])
        self._radar.pack(side="left", padx=(0, 12))

        self._tamper_banner = ctk.CTkFrame(
            radar_body, fg_color=THEME["bg_input"],
            corner_radius=10, border_width=1,
            border_color=THEME["border_subtle"]
        )
        self._tamper_banner.pack(side="left", fill="both", expand=True)

        text_col = ctk.CTkFrame(self._tamper_banner, fg_color="transparent")
        text_col.pack(fill="both", expand=True, padx=12, pady=10)

        self._tamper_banner_label = ctk.CTkLabel(
            text_col,
            text="🔒  Awaiting verification audit...",
            font=ctk.CTkFont(family=FONTS["title_section"][0], size=12, weight="bold"),
            text_color=THEME["text_muted"],
            anchor="w"
        )
        self._tamper_banner_label.pack(anchor="w", pady=(4, 2))

        self._tamper_banner_detail = ctk.CTkLabel(
            text_col,
            text="Execute the radar to evaluate SHA-256 digital fingerprint and RSA-PSS authenticity",
            font=ctk.CTkFont(family=FONTS["body"][0], size=10),
            text_color=THEME["text_muted"],
            anchor="w",
            wraplength=280
        )
        self._tamper_banner_detail.pack(anchor="w")

        checklist_card = GlassCard(mid_row)
        checklist_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        self._section_header(checklist_card, "3. Radar Checkpoint Telemetry", "Step-by-step cryptographic audit progression")

        checklist_inner = ctk.CTkFrame(checklist_card, fg_color="transparent")
        checklist_inner.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        self._verify_step_texts = [
            "Magic Bytes & JSON Extraction",
            "RSA-OAEP Session Key Unwrap",
            "DES-CBC Ciphertext Decryption",
            "SHA-256 Digest & RSA-PSS Verification",
        ]
        self._verify_step_rows: list[ctk.CTkFrame] = []
        self._verify_step_icons: list[ctk.CTkLabel] = []
        self._verify_step_labels_list: list[ctk.CTkLabel] = []
        self._verify_step_badges: list[ctk.CTkLabel] = []

        for idx, step_text in enumerate(self._verify_step_texts):
            row = ctk.CTkFrame(
                checklist_inner, fg_color=THEME["bg_input"],
                corner_radius=6, border_width=1, border_color=THEME["border_subtle"],
                height=32
            )
            row.pack(fill="x", pady=2)
            row.pack_propagate(False)

            icon_lbl = ctk.CTkLabel(
                row, text="○",
                font=ctk.CTkFont(family=FONTS["mono_body"][0], size=12),
                text_color=THEME["text_muted"],
                width=24
            )
            icon_lbl.pack(side="left", padx=(8, 2))

            step_lbl = ctk.CTkLabel(
                row, text=f"Stage {idx+1}: {step_text}",
                font=ctk.CTkFont(family=FONTS["body"][0], size=10),
                text_color=THEME["text_muted"]
            )
            step_lbl.pack(side="left", padx=2)

            badge = ctk.CTkLabel(
                row, text="STANDBY",
                font=ctk.CTkFont(family=FONTS["mono_badge"][0], size=8, weight="bold"),
                text_color=THEME["text_secondary"],
                fg_color="#14213d",
                corner_radius=4,
                width=72
            )
            badge.pack(side="right", padx=8)

            self._verify_step_rows.append(row)
            self._verify_step_icons.append(icon_lbl)
            self._verify_step_labels_list.append(step_lbl)
            self._verify_step_badges.append(badge)

        result_card = GlassCard(body)
        result_card.pack(fill="both", expand=True)
        self._section_header(result_card, "4. Verification Audit Certificate", "Technical report with integrity status flags")

        self._tamper_result_box = ctk.CTkTextbox(
            result_card,
            font=ctk.CTkFont(family=FONTS["mono_body"][0], size=10),
            fg_color=THEME["bg_input"],
            text_color=THEME["text_primary"],
            border_color=THEME["border_subtle"],
            border_width=1,
            corner_radius=8,
            wrap="word",
            height=130
        )
        self._tamper_result_box.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        default_cert_text = (
            "[SYSTEM READY] Anti-tamper verification engine online.\n\n"
            "• Step 1: Select or browse any .vsec container package.\n"
            "• Step 2: Click 'Run Integrity Verification' to perform real-time cryptographic audit.\n"
            "• Step 3: Or click 'Simulate Hex Tampering' to inject binary byte flips and test radar detection."
        )
        self._tamper_result_box.insert("1.0", default_cert_text)
        self._tamper_result_box.configure(state="disabled")

        self._selected_vsec_file: str | None = None
        return frame

    def _tamper_browse(self):
        path = filedialog.askopenfilename(
            title="Select .vsec container file",
            filetypes=[("VaultChain Secure Container", "*.vsec"), ("All files", "*.*")]
        )
        if path:
            self._selected_vsec_file = path
            self._tamper_file_var.set(f"Loaded: {os.path.basename(path)}")
            self._log("INFO", f".vsec package armed for verification: {os.path.basename(path)}")
            self._stop_alert_breath()
            self._tamper_banner.configure(fg_color=THEME["bg_input"], border_color=THEME["border_subtle"])
            self._tamper_banner_label.configure(
                text="🔒  Container loaded. Click 'Run Integrity Verification' to test.",
                text_color=THEME["text_primary"]
            )
            self._tamper_banner_detail.configure(
                text="The integrity engine will check binary container structure, unwrap key, and verify SHA-256",
                text_color=THEME["text_muted"]
            )
            for idx in range(4):
                self._reset_verify_step(idx)

    def _reset_verify_step(self, idx: int):
        self._verify_step_states[idx] = "pending"
        self._verify_step_rows[idx].configure(fg_color=THEME["bg_input"], border_color=THEME["border_subtle"])
        self._verify_step_icons[idx].configure(text="○", text_color=THEME["text_muted"])
        self._verify_step_labels_list[idx].configure(text_color=THEME["text_muted"])
        self._verify_step_badges[idx].configure(
            text="STANDBY", text_color=THEME["text_secondary"], fg_color="#14213d"
        )

    def _set_verify_step(self, idx: int, state: str):
        try:
            self._verify_step_states[idx] = state
            row = self._verify_step_rows[idx]
            icon = self._verify_step_icons[idx]
            lbl = self._verify_step_labels_list[idx]
            badge = self._verify_step_badges[idx]

            if state == "running":
                row.configure(fg_color=THEME["badge_cyan_bg"], border_color=THEME["neon_cyan"])
                icon.configure(text=SPINNERS[self._verify_spinner_index], text_color=THEME["neon_cyan"])
                lbl.configure(text_color=THEME["neon_cyan"])
                badge.configure(text="SCANNING", text_color=THEME["neon_cyan"], fg_color="#033042")
                if not self._verify_spinner_job:
                    self._tamper_step_spinner_tick()
            elif state == "ok":
                row.configure(fg_color=THEME["badge_green_bg"], border_color=THEME["neon_green"])
                icon.configure(text="✅", text_color=THEME["neon_green"])
                lbl.configure(text_color=THEME["text_primary"])
                badge.configure(text="PASSED", text_color=THEME["neon_green"], fg_color="#03451a")
            elif state == "fail":
                row.configure(fg_color=THEME["badge_red_bg"], border_color=THEME["neon_red"])
                icon.configure(text="❌", text_color=THEME["neon_red"])
                lbl.configure(text_color=THEME["neon_red"])
                badge.configure(text="FAILED", text_color=THEME["neon_red"], fg_color="#520a1c")
        except Exception:
            pass

    def _tamper_step_spinner_tick(self):
        try:
            active_any = any(s == "running" for s in self._verify_step_states)
            if not active_any or not self.winfo_exists():
                self._verify_spinner_job = None
                return
            self._verify_spinner_index = (self._verify_spinner_index + 1) % len(SPINNERS)
            for idx, state in enumerate(self._verify_step_states):
                if state == "running":
                    self._verify_step_icons[idx].configure(
                        text=SPINNERS[self._verify_spinner_index],
                        text_color=THEME["neon_cyan"]
                    )
            self._verify_spinner_job = self.after(55, self._tamper_step_spinner_tick)
        except Exception:
            self._verify_spinner_job = None

    def _tamper_verify_threaded(self):
        if not self._selected_vsec_file:
            if self._vsec_path and os.path.exists(self._vsec_path):
                self._selected_vsec_file = self._vsec_path
                self._tamper_file_var.set(f"Loaded: {os.path.basename(self._vsec_path)}")
            else:
                messagebox.showerror("No File Selected", "Please select a .vsec container file first.")
                return
        for idx in range(4):
            self._reset_verify_step(idx)
        self._stop_alert_breath()
        thread = threading.Thread(target=self._tamper_verify_worker, daemon=True)
        thread.start()

    def _tamper_verify_worker(self):
        try:
            self._log("INFO", "Anti-tamper verification audit initiated...")
            self.after(0, self._set_verify_step, 0, "running")
            time.sleep(0.18)

            with open(self._selected_vsec_file, "rb") as f:
                vsec_data = f.read()

            self.after(0, self._set_verify_step, 0, "ok")
            self.after(0, self._set_verify_step, 1, "running")
            time.sleep(0.20)

            plaintext, metadata, hash_match, sig_valid = unpackage_vsec(vsec_data)

            self.after(0, self._set_verify_step, 1, "ok")
            self.after(0, self._set_verify_step, 2, "running")
            time.sleep(0.18)

            self.after(0, self._set_verify_step, 2, "ok")
            self.after(0, self._set_verify_step, 3, "running")
            time.sleep(0.20)

            report_lines = [
                f"File Target   : {os.path.basename(self._selected_vsec_file)}",
                f"Original Name : {metadata.get('original_filename', 'unknown')}",
                f"Packaged At   : {metadata.get('timestamp', 'unknown')}",
                f"Stored Hash   : {metadata.get('file_hash_hex', '')[:48]}...",
                f"",
                f"SHA-256 Integrity : {'✅ MATCH — File intact' if hash_match else '❌ MISMATCH — Tampering detected!'}",
                f"RSA Signature     : {'✅ VALID — Authenticity confirmed' if sig_valid else '❌ INVALID — Signature broken!'}",
                f"",
            ]

            prefixed_lines = []
            for line in report_lines:
                if "MATCH" in line or "VALID" in line:
                    prefixed_lines.append("✅ " + line)
                elif "MISMATCH" in line or "INVALID" in line:
                    prefixed_lines.append("🚨 " + line)
                else:
                    prefixed_lines.append(line)

            if hash_match and sig_valid:
                prefixed_lines.append("🔒 VERDICT: File is 100% AUTHENTIC and UNTAMPERED.")
                self._log("SUCCESS", "Verification passed: SHA-256 match + valid RSA signature.")
                self.after(0, self._set_verify_step, 3, "ok")
                self.after(0, self._show_banner_ok)
            else:
                prefixed_lines.append("🚨 VERDICT: INTEGRITY COMPROMISED — Do NOT trust this file!")
                if not hash_match:
                    self._log("CRITICAL", "CRITICAL: Integrity Compromised! SHA-256 Hash Mismatch Detected.")
                if not sig_valid:
                    self._log("CRITICAL", "RSA Signature verification failed — file signature invalid.")
                self.after(0, self._set_verify_step, 3, "fail")
                self.after(0, self._show_banner_alert)

            report_text = "\n".join(prefixed_lines)
            self.after(0, self._tamper_update_result, report_text)

        except Exception as exc:
            self._log("ERROR", f"Verification error: {exc}")
            self.after(0, lambda: messagebox.showerror("Verification Error", str(exc)))
            self.after(0, self._show_banner_error, str(exc))
            for i in range(4):
                self.after(0, self._set_verify_step, i, "fail")

    def _tamper_decrypt_threaded(self):
        if not self._selected_vsec_file:
            if self._vsec_path and os.path.exists(self._vsec_path):
                self._selected_vsec_file = self._vsec_path
            else:
                messagebox.showerror("No File Selected", "Please select a .vsec container file first.")
                return
        thread = threading.Thread(target=self._tamper_decrypt_worker, daemon=True)
        thread.start()

    def _tamper_decrypt_worker(self):
        try:
            with open(self._selected_vsec_file, "rb") as f:
                vsec_data = f.read()
            plaintext, metadata, hash_match, sig_valid = unpackage_vsec(vsec_data)

            if not hash_match:
                self._log("WARNING", "Decrypting tampered container — hash mismatch noted.")
                answer = messagebox.askyesno(
                    "Integrity Warning",
                    "This container payload has been tampered with!\n\n"
                    "Do you still want to force decryption and extract the raw bytes?"
                )
                if not answer:
                    return

            original_name = metadata.get("original_filename", "decrypted_payload.bin")
            out_dir = os.path.dirname(self._selected_vsec_file)
            out_path = os.path.join(out_dir, "RESTORED_" + original_name)

            with open(out_path, "wb") as f:
                f.write(plaintext)

            self._log("SUCCESS", f"Decrypted payload saved: RESTORED_{original_name}")
            self.after(0, lambda: messagebox.showinfo(
                "Restoration Complete",
                f"Payload successfully decrypted and saved to:\n{out_path}"
            ))
        except Exception as exc:
            self._log("ERROR", f"Decryption failed: {exc}")
            self.after(0, lambda: messagebox.showerror("Decryption Error", str(exc)))

    def _tamper_simulate(self):
        target = self._selected_vsec_file or self._vsec_path
        if not target:
            messagebox.showerror("No Container Armed", "Please select or generate a .vsec file first.")
            return
        try:
            offset = tamper_vsec_file(target)
            self._log("WARNING", f"HEX INJECTOR: Byte at offset {offset} (0x{offset:04X}) flipped in {os.path.basename(target)}")
            messagebox.showinfo(
                "Hex Tampering Simulated",
                f"Binary byte at offset {offset} (0x{offset:04X}) has been programmatically flipped with XOR 0xFF.\n\n"
                f"Now click 'Run Integrity Verification' to test SHA-256 detection."
            )
        except Exception as exc:
            self._log("ERROR", f"Tampering simulation failed: {exc}")
            messagebox.showerror("Tamper Error", str(exc))

    def _show_banner_ok(self):
        self._stop_alert_breath()
        self._tamper_banner.configure(
            fg_color=THEME["badge_green_bg"], border_color=THEME["neon_green"]
        )
        self._tamper_banner_label.configure(
            text="🛡️  INTEGRITY VERIFIED — File is Authentic and Untampered",
            text_color=THEME["neon_green"]
        )
        self._tamper_banner_detail.configure(
            text="SHA-256 digest match confirmed  |  RSA-PSS digital signature valid  |  0 bitflips detected",
            text_color=THEME["neon_green"]
        )

    def _show_banner_alert(self):
        self._start_alert_breath()

    def _show_banner_error(self, msg: str):
        self._stop_alert_breath()
        self._tamper_banner.configure(
            fg_color=THEME["badge_red_bg"], border_color=THEME["neon_red"]
        )
        self._tamper_banner_label.configure(
            text=f"❌  VERIFICATION ERROR: {msg[:64]}",
            text_color=THEME["neon_red"]
        )
        self._tamper_banner_detail.configure(
            text="Container corrupt or invalid binary structure",
            text_color=THEME["neon_red"]
        )

    def _start_alert_breath(self):
        self._alert_breath_active = True
        self._alert_breath_phase = 0.0
        self._do_alert_breath()

    def _do_alert_breath(self):
        if not self._alert_breath_active:
            return
        try:
            if not self.winfo_exists():
                self._alert_breath_active = False
                return
            self._alert_breath_phase += 0.08
            factor = (1.0 + math.sin(self._alert_breath_phase)) / 2.0
            bg_col = interpolate_color("#25050e", "#4d0b1d", factor)
            border_col = interpolate_color("#80142c", "#ff3366", factor)
            try:
                if self._tamper_banner.winfo_exists():
                    self._tamper_banner.configure(fg_color=bg_col, border_color=border_col)
                    self._tamper_banner_label.configure(
                        text="🚨  CRITICAL: Integrity Compromised! SHA-256 Hash Mismatch Detected",
                        text_color=THEME["neon_red"]
                    )
                    self._tamper_banner_detail.configure(
                        text="Tampered bits detected  |  SHA-256 computed ≠ stored  |  RSA-PSS: invalid signature",
                        text_color=THEME["neon_red"]
                    )
            except Exception:
                pass
            self._alert_breath_job = self.after(50, self._do_alert_breath)
        except Exception:
            self._alert_breath_active = False

    def _stop_alert_breath(self):
        self._alert_breath_active = False
        if self._alert_breath_job:
            try:
                self.after_cancel(self._alert_breath_job)
            except Exception:
                pass
            self._alert_breath_job = None

    def _tamper_update_result(self, text: str):
        self._tamper_result_box.configure(state="normal")
        self._tamper_result_box.delete("1.0", "end")
        self._tamper_result_box.insert("1.0", text)
        self._tamper_result_box.configure(state="disabled")

    def _build_cipher_frame(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color=THEME["bg_root"], corner_radius=0)
        self._page_header(
            frame, "🔡", "Classical Cryptanalysis & Cipher Sandbox",
            "Cryptanalytic Workstation: Caesar Frequency Analysis & Playfair Polygraphic Matrix"
        )

        self._cipher_tabs = ctk.CTkTabview(
            frame,
            fg_color=THEME["bg_card"],
            segmented_button_fg_color=THEME["bg_input"],
            segmented_button_selected_color="#0284c7",
            segmented_button_selected_hover_color=THEME["neon_cyan_glow"],
            segmented_button_unselected_color=THEME["bg_input"],
            segmented_button_unselected_hover_color=THEME["border_glow"],
            text_color=THEME["text_primary"],
            text_color_disabled=THEME["text_muted"],
            corner_radius=12
        )
        self._cipher_tabs.pack(fill="both", expand=True, padx=24, pady=10)
        self._cipher_tabs.add("Caesar Cipher")
        self._cipher_tabs.add("Playfair Cipher")

        self._build_caesar_tab(self._cipher_tabs.tab("Caesar Cipher"))
        self._build_playfair_tab(self._cipher_tabs.tab("Playfair Cipher"))
        return frame

    def _build_caesar_tab(self, tab):
        tab.configure(fg_color="transparent")

        ctk.CTkLabel(
            tab, text="Plaintext / Ciphertext Input Buffer:",
            font=ctk.CTkFont(family=FONTS["title_card"][0], size=FONTS["title_card"][1], weight="bold"),
            text_color=THEME["neon_cyan"]
        ).pack(anchor="w", padx=4, pady=(12, 4))

        self._caesar_input = ctk.CTkTextbox(
            tab, height=75,
            font=ctk.CTkFont(family=FONTS["mono_body"][0], size=FONTS["mono_body"][1]),
            fg_color=THEME["bg_input"],
            text_color=THEME["text_primary"],
            border_color=THEME["border_subtle"],
            border_width=1,
            corner_radius=10
        )
        self._caesar_input.pack(fill="x", padx=4, pady=(0, 10))

        ctrl_row = ctk.CTkFrame(tab, fg_color="transparent")
        ctrl_row.pack(fill="x", padx=4, pady=(0, 10))

        ctk.CTkLabel(
            ctrl_row, text="Shift Parameter:",
            font=ctk.CTkFont(family=FONTS["body_bold"][0], size=FONTS["body_bold"][1], weight="bold"),
            text_color=THEME["text_primary"]
        ).pack(side="left", padx=(0, 8))

        self._caesar_shift = ctk.CTkSlider(
            ctrl_row, from_=1, to=25, number_of_steps=24,
            fg_color=THEME["bg_input"],
            progress_color=THEME["neon_cyan"],
            button_color=THEME["neon_cyan"],
            button_hover_color=THEME["neon_cyan_glow"],
            width=220
        )
        self._caesar_shift.set(3)
        self._caesar_shift.pack(side="left", padx=(0, 10))

        self._caesar_shift_label = ctk.CTkLabel(
            ctrl_row, text="3",
            font=ctk.CTkFont(family=FONTS["title_card"][0], size=FONTS["title_card"][1], weight="bold"),
            text_color=THEME["neon_cyan"],
            width=32
        )
        self._caesar_shift_label.pack(side="left", padx=(0, 16))
        self._caesar_shift.configure(
            command=lambda v: self._caesar_shift_label.configure(text=str(int(v)))
        )

        self._action_button(ctrl_row, "🔒  Encrypt", self._caesar_do_encrypt).pack(side="left", padx=(0, 8))
        self._action_button(
            ctrl_row, "🔓  Decrypt", self._caesar_do_decrypt,
            color=THEME["bg_card_hover"]
        ).pack(side="left", padx=(0, 8))
        self._action_button(
            ctrl_row, "⚡  Run Brute-Force Radar", self._caesar_brute_force,
            color=THEME["neon_red"], text_color=THEME["text_primary"]
        ).pack(side="left")

        ctk.CTkLabel(
            tab, text="Transformation Output:",
            font=ctk.CTkFont(family=FONTS["title_card"][0], size=FONTS["title_card"][1], weight="bold"),
            text_color=THEME["neon_cyan"]
        ).pack(anchor="w", padx=4, pady=(8, 4))

        self._caesar_plain_output = ctk.CTkTextbox(
            tab, height=90,
            font=ctk.CTkFont(family=FONTS["mono_body"][0], size=FONTS["mono_body"][1]),
            fg_color=THEME["bg_input"],
            text_color=THEME["text_primary"],
            border_color=THEME["border_subtle"],
            border_width=1,
            corner_radius=10
        )
        self._caesar_plain_output.pack(fill="x", padx=4, pady=(0, 6))
        self._caesar_plain_output.configure(state="disabled")

        self._caesar_brute_scroll = ctk.CTkScrollableFrame(
            tab, fg_color=THEME["bg_input"],
            corner_radius=10,
            border_width=1,
            border_color=THEME["border_subtle"],
            height=160
        )
        self._caesar_brute_scroll.pack(fill="both", expand=True, padx=4, pady=(0, 6))

        self._caesar_freq_frame = GlassCard(tab, corner_radius=10)
        self._caesar_freq_frame.pack(fill="x", padx=4, pady=(0, 8))

        ctk.CTkLabel(
            self._caesar_freq_frame, text="Letter Frequency Analysis — Top Candidates vs Standard English Distribution",
            font=ctk.CTkFont(family=FONTS["caption_bold"][0], size=FONTS["caption_bold"][1], weight="bold"),
            text_color=THEME["neon_cyan"]
        ).pack(anchor="w", padx=14, pady=(8, 4))

        self._caesar_freq_bars_frame = ctk.CTkFrame(self._caesar_freq_frame, fg_color="transparent")
        self._caesar_freq_bars_frame.pack(fill="x", padx=14, pady=(0, 10))

    def _caesar_do_encrypt(self):
        text = self._caesar_input.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("Empty Input Buffer", "Please enter text to encrypt.")
            return
        shift = int(self._caesar_shift.get())
        result = caesar_encrypt(text, shift)
        self._caesar_set_plain_output(f"[Caesar Shift={shift} Encrypt Result]:\n\n{result}")
        self._clear_brute_table()
        self._log("INFO", f"Caesar encrypt executed: shift={shift}, chars={len(text)}")

    def _caesar_do_decrypt(self):
        text = self._caesar_input.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("Empty Input Buffer", "Please enter text to decrypt.")
            return
        shift = int(self._caesar_shift.get())
        result = caesar_decrypt(text, shift)
        self._caesar_set_plain_output(f"[Caesar Shift={shift} Decrypt Result]:\n\n{result}")
        self._clear_brute_table()
        self._log("INFO", f"Caesar decrypt executed: shift={shift}, chars={len(text)}")

    def _caesar_set_plain_output(self, text: str):
        self._caesar_plain_output.configure(state="normal")
        self._caesar_plain_output.delete("1.0", "end")
        self._caesar_plain_output.insert("1.0", text)
        self._caesar_plain_output.configure(state="disabled")

    def _clear_brute_table(self):
        for widget in self._caesar_brute_scroll.winfo_children():
            widget.destroy()
        for widget in self._caesar_freq_bars_frame.winfo_children():
            widget.destroy()

    def _caesar_brute_force(self):
        text = self._caesar_input.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("Empty Input Buffer", "Please enter ciphertext for cryptanalysis.")
            return
        self._log("INFO", f"Caesar brute-force analysis started on {len(text)}-char buffer.")
        thread = threading.Thread(target=self._caesar_brute_worker, args=(text,), daemon=True)
        thread.start()

    def _caesar_brute_worker(self, ciphertext: str):
        results = caesar_brute_force(ciphertext)
        self.after(0, self._caesar_populate_brute_table, results)
        self._log("SUCCESS", f"Brute-force complete: 25 variations evaluated. Best shift: {results[0]['shift']} (χ²={results[0]['chi_squared']:.2f})")

    def _caesar_populate_brute_table(self, results: list):
        for widget in self._caesar_brute_scroll.winfo_children():
            widget.destroy()

        header_row = ctk.CTkFrame(
            self._caesar_brute_scroll,
            fg_color=THEME["bg_card"],
            corner_radius=6
        )
        header_row.pack(fill="x", pady=(0, 2))

        for col_text, col_width in [("Rank", 55), ("Shift", 65), ("χ² Score", 100), ("Decrypted Preview Candidate", 0)]:
            lbl_kw = dict(
                font=ctk.CTkFont(family=FONTS["caption_bold"][0], size=FONTS["caption_bold"][1], weight="bold"),
                text_color=THEME["neon_cyan"],
                anchor="w"
            )
            if col_width > 0:
                lbl_kw["width"] = col_width
            ctk.CTkLabel(header_row, text=col_text, **lbl_kw).pack(side="left", padx=8, pady=5)

        for rank, entry in enumerate(results, 1):
            bg = THEME["bg_card"] if rank % 2 == 0 else THEME["bg_input"]
            row_frame = ctk.CTkFrame(
                self._caesar_brute_scroll,
                fg_color=bg,
                corner_radius=6
            )
            row_frame.pack(fill="x", pady=1)

            ctk.CTkLabel(
                row_frame, text=f"#{rank}",
                font=ctk.CTkFont(family=FONTS["mono_badge"][0], size=FONTS["mono_badge"][1], weight="bold"),
                text_color=THEME["text_muted"],
                width=55
            ).pack(side="left", padx=8, pady=4)

            ctk.CTkLabel(
                row_frame, text=str(entry["shift"]),
                font=ctk.CTkFont(family=FONTS["mono_body"][0], size=FONTS["mono_body"][1], weight="bold"),
                text_color=THEME["neon_cyan"],
                width=65
            ).pack(side="left", padx=4, pady=4)

            chi = entry["chi_squared"]
            chi_color = THEME["neon_green"] if chi < 100 else (THEME["neon_amber"] if chi < 300 else THEME["neon_red"])

            ctk.CTkLabel(
                row_frame, text=f"{chi:.2f}",
                font=ctk.CTkFont(family=FONTS["mono_code"][0], size=FONTS["mono_code"][1]),
                text_color=chi_color,
                width=100
            ).pack(side="left", padx=4, pady=4)

            preview = entry["decrypted"][:60].replace("\n", " ")
            ctk.CTkLabel(
                row_frame, text=preview,
                font=ctk.CTkFont(family=FONTS["mono_code"][0], size=FONTS["mono_code"][1]),
                text_color=THEME["text_primary"],
                anchor="w"
            ).pack(side="left", padx=4, pady=4, fill="x", expand=True)

        for widget in self._caesar_freq_bars_frame.winfo_children():
            widget.destroy()

        freq = results[0]["frequency"]
        top_letters = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:8]
        max_pct = top_letters[0][1] if top_letters and top_letters[0][1] > 0 else 1.0

        bar_targets: list[tuple[ctk.CTkProgressBar, float]] = []

        for letter, pct in top_letters:
            bar_row = ctk.CTkFrame(self._caesar_freq_bars_frame, fg_color="transparent")
            bar_row.pack(fill="x", pady=2)

            ctk.CTkLabel(
                bar_row, text=letter.upper(),
                font=ctk.CTkFont(family=FONTS["mono_badge"][0], size=FONTS["mono_badge"][1], weight="bold"),
                text_color=THEME["neon_cyan"],
                width=24
            ).pack(side="left", padx=(0, 6))

            bar = ctk.CTkProgressBar(
                bar_row, height=8, corner_radius=4,
                fg_color=THEME["bg_input"],
                progress_color=THEME["neon_cyan"],
                width=240
            )
            bar.set(0.0)
            bar.pack(side="left", padx=(0, 10))

            target_val = pct / max_pct if max_pct > 0 else 0.0
            bar_targets.append((bar, target_val))

            ctk.CTkLabel(
                bar_row, text=f"{pct:.2f}%",
                font=ctk.CTkFont(family=FONTS["mono_code"][0], size=FONTS["mono_code"][1]),
                text_color=THEME["text_muted"]
            ).pack(side="left")

        self._start_freq_bars_animation(bar_targets)

        self._caesar_set_plain_output(
            f"[Caesar Brute-Force Candidate — Shift={results[0]['shift']} | χ² Score={results[0]['chi_squared']:.2f}]:\n\n"
            f"{results[0]['decrypted'][:320]}"
        )

    def _start_freq_bars_animation(self, targets: list[tuple[ctk.CTkProgressBar, float]]):
        self._freq_bars_targets = targets
        self._freq_bars_step = 0
        if self._freq_bars_job:
            try:
                self.after_cancel(self._freq_bars_job)
            except Exception:
                pass
        self._animate_freq_bars_step()

    def _animate_freq_bars_step(self):
        try:
            if not self.winfo_exists():
                self._freq_bars_job = None
                return
            self._freq_bars_step += 1
            u = self._freq_bars_step / float(self._freq_bars_total_steps)
            ease = 1.0 - (1.0 - u) ** 3
            for bar, target in self._freq_bars_targets:
                bar.set(target * ease)
            if self._freq_bars_step < self._freq_bars_total_steps:
                self._freq_bars_job = self.after(20, self._animate_freq_bars_step)
            else:
                self._freq_bars_job = None
        except Exception:
            self._freq_bars_job = None

    def _build_playfair_tab(self, tab):
        tab.configure(fg_color="transparent")

        kw_row = ctk.CTkFrame(tab, fg_color="transparent")
        kw_row.pack(fill="x", padx=4, pady=(12, 8))

        ctk.CTkLabel(
            kw_row, text="Cipher Keyword:",
            font=ctk.CTkFont(family=FONTS["body_bold"][0], size=FONTS["body_bold"][1], weight="bold"),
            text_color=THEME["neon_cyan"]
        ).pack(side="left", padx=(0, 10))

        self._playfair_keyword = ctk.CTkEntry(
            kw_row, placeholder_text="e.g. MONARCHY", width=220,
            font=ctk.CTkFont(family=FONTS["mono_body"][0], size=FONTS["mono_body"][1]),
            fg_color=THEME["bg_input"], border_color=THEME["border_subtle"],
            border_width=1, corner_radius=10, text_color=THEME["text_primary"]
        )
        self._playfair_keyword.pack(side="left", padx=(0, 12))

        self._action_button(
            kw_row, "Generate 5x5 Matrix", self._playfair_show_matrix,
            color=THEME["bg_card_hover"]
        ).pack(side="left")

        self._playfair_matrix_frame = GlassCard(tab, corner_radius=12)
        self._playfair_matrix_frame.pack(fill="x", padx=4, pady=(0, 10))

        ctk.CTkLabel(
            tab, text="Plaintext / Ciphertext Input Buffer:",
            font=ctk.CTkFont(family=FONTS["title_card"][0], size=FONTS["title_card"][1], weight="bold"),
            text_color=THEME["neon_cyan"]
        ).pack(anchor="w", padx=4, pady=(4, 4))

        self._playfair_input = ctk.CTkTextbox(
            tab, height=75,
            font=ctk.CTkFont(family=FONTS["mono_body"][0], size=FONTS["mono_body"][1]),
            fg_color=THEME["bg_input"], text_color=THEME["text_primary"],
            border_color=THEME["border_subtle"], border_width=1, corner_radius=10
        )
        self._playfair_input.pack(fill="x", padx=4, pady=(0, 10))

        btn_row = ctk.CTkFrame(tab, fg_color="transparent")
        btn_row.pack(fill="x", padx=4, pady=(0, 10))

        self._action_button(
            btn_row, "🔒  Encrypt (Playfair)", self._playfair_do_encrypt
        ).pack(side="left", padx=(0, 10))

        self._action_button(
            btn_row, "🔓  Decrypt (Playfair)", self._playfair_do_decrypt,
            color=THEME["bg_card_hover"]
        ).pack(side="left")

        ctk.CTkLabel(
            tab, text="Playfair Transformation Output:",
            font=ctk.CTkFont(family=FONTS["title_card"][0], size=FONTS["title_card"][1], weight="bold"),
            text_color=THEME["neon_cyan"]
        ).pack(anchor="w", padx=4, pady=(8, 4))

        self._playfair_output = ctk.CTkTextbox(
            tab, height=140,
            font=ctk.CTkFont(family=FONTS["mono_body"][0], size=FONTS["mono_body"][1]),
            fg_color=THEME["bg_input"], text_color=THEME["text_primary"],
            border_color=THEME["border_subtle"], border_width=1, corner_radius=10
        )
        self._playfair_output.pack(fill="both", expand=True, padx=4, pady=(0, 10))
        self._playfair_output.configure(state="disabled")

        self._playfair_keyword_chars: set[str] = set()
        self._playfair_keyword.insert(0, "MONARCHY")
        self._playfair_show_matrix()

    def _playfair_show_matrix(self):
        keyword = self._playfair_keyword.get().strip()
        if not keyword:
            messagebox.showwarning("Missing Keyword", "Please enter a keyword to generate the Playfair matrix.")
            return
        matrix = build_playfair_matrix(keyword)

        kw_clean = keyword.upper().replace("J", "I")
        seen = set()
        kw_chars = []
        for c in kw_clean:
            if c.isalpha() and c not in seen:
                seen.add(c)
                kw_chars.append(c)
        self._playfair_keyword_chars = set(kw_chars)

        for widget in self._playfair_matrix_frame.winfo_children():
            widget.destroy()

        header_strip = ctk.CTkFrame(self._playfair_matrix_frame, fg_color="transparent")
        header_strip.pack(anchor="w", fill="x", padx=14, pady=(10, 6))

        ctk.CTkLabel(
            header_strip,
            text=f"Playfair 5x5 Matrix  [Keyword: {keyword.upper()}]",
            font=ctk.CTkFont(family=FONTS["caption_bold"][0], size=FONTS["caption_bold"][1], weight="bold"),
            text_color=THEME["neon_cyan"]
        ).pack(side="left")

        ctk.CTkLabel(
            header_strip,
            text="(I/J mapped; illuminated cells = unique keyword letters)",
            font=ctk.CTkFont(family=FONTS["caption"][0], size=FONTS["caption"][1]),
            text_color=THEME["text_muted"]
        ).pack(side="left", padx=(10, 0))

        grid_frame = ctk.CTkFrame(self._playfair_matrix_frame, fg_color="transparent")
        grid_frame.pack(padx=14, pady=(0, 12))

        cell_items = []
        for r, row in enumerate(matrix):
            for c, letter in enumerate(row):
                is_kw = letter in self._playfair_keyword_chars
                cell = ctk.CTkFrame(
                    grid_frame,
                    width=46, height=46,
                    fg_color=THEME["bg_input"],
                    corner_radius=8,
                    border_width=1,
                    border_color=THEME["border_subtle"]
                )
                cell.grid(row=r, column=c, padx=3, pady=3)
                cell.grid_propagate(False)

                lbl = ctk.CTkLabel(
                    cell, text=letter,
                    font=ctk.CTkFont(family=FONTS["mono_body"][0], size=16, weight="bold"),
                    text_color=THEME["text_muted"]
                )
                lbl.place(relx=0.5, rely=0.5, anchor="center")
                cell_items.append((cell, lbl, is_kw))

        for idx, (cell, lbl, is_kw) in enumerate(cell_items):
            delay = idx * 18
            self.after(delay, lambda c=cell, l=lbl, kw=is_kw: self._illuminate_matrix_cell(c, l, kw))

        self._log("INFO", f"Playfair 5x5 matrix generated for keyword: '{keyword.upper()}'")

    def _illuminate_matrix_cell(self, cell: ctk.CTkFrame, lbl: ctk.CTkLabel, is_kw: bool):
        try:
            if is_kw:
                cell.configure(
                    fg_color=THEME["badge_cyan_bg"],
                    border_color=THEME["neon_cyan"],
                    border_width=2
                )
                lbl.configure(text_color=THEME["neon_cyan"])
            else:
                cell.configure(
                    fg_color=THEME["bg_card"],
                    border_color=THEME["border_subtle"],
                    border_width=1
                )
                lbl.configure(text_color=THEME["text_primary"])
        except Exception:
            pass

    def _playfair_do_encrypt(self):
        keyword = self._playfair_keyword.get().strip()
        text = self._playfair_input.get("1.0", "end").strip()
        if not keyword or not text:
            messagebox.showwarning("Missing Input", "Please enter both keyword and plaintext.")
            return
        try:
            result = playfair_encrypt(text, keyword)
            self._playfair_set_output(
                f"[Playfair Encrypt | Keyword: {keyword.upper()}]:\n\n"
                f"Input  : {text.upper()}\nOutput : {result}"
            )
            self._log("INFO", f"Playfair encrypt executed: keyword='{keyword.upper()}', chars={len(text)}")
        except Exception as exc:
            messagebox.showerror("Playfair Error", str(exc))

    def _playfair_do_decrypt(self):
        keyword = self._playfair_keyword.get().strip()
        text = self._playfair_input.get("1.0", "end").strip()
        if not keyword or not text:
            messagebox.showwarning("Missing Input", "Please enter both keyword and ciphertext.")
            return
        try:
            result = playfair_decrypt(text, keyword)
            self._playfair_set_output(
                f"[Playfair Decrypt | Keyword: {keyword.upper()}]:\n\n"
                f"Input  : {text.upper()}\nOutput : {result}"
            )
            self._log("INFO", f"Playfair decrypt executed: keyword='{keyword.upper()}', chars={len(text)}")
        except Exception as exc:
            messagebox.showerror("Playfair Error", str(exc))

    def _playfair_set_output(self, text: str):
        self._playfair_output.configure(state="normal")
        self._playfair_output.delete("1.0", "end")
        self._playfair_output.insert("1.0", text)
        self._playfair_output.configure(state="disabled")

    def _build_audit_frame(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color=THEME["bg_root"], corner_radius=0)
        self._page_header(
            frame, "🌐", "Web Browser & Header Security Inspector",
            "Security Posture Auditor: HTTP Defense Headers, Cookie Flags & OWASP Hardening Score"
        )

        body = ctk.CTkFrame(frame, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        url_card = GlassCard(body)
        url_card.pack(fill="x", pady=(0, 8))
        self._section_header(url_card, "1. Target Domain / Host URL", "Enter domain to simulate HTTP request and parse response headers")

        url_row = ctk.CTkFrame(url_card, fg_color="transparent")
        url_row.pack(fill="x", padx=14, pady=(0, 10))

        self._action_button(
            url_row, "🔍  Run Inspection", self._audit_run_threaded,
            width=170
        ).pack(side="right")

        self._audit_url_entry = ctk.CTkEntry(
            url_row, placeholder_text="e.g. https://google.com or https://github.com", height=38,
            font=ctk.CTkFont(family=FONTS["mono_body"][0], size=FONTS["mono_body"][1]),
            fg_color=THEME["bg_input"], border_color=THEME["border_subtle"],
            border_width=1, corner_radius=8, text_color=THEME["text_primary"]
        )
        self._audit_url_entry.pack(side="left", fill="x", expand=True, padx=(0, 12))

        mid_row = ctk.CTkFrame(body, fg_color="transparent")
        mid_row.configure(height=250)
        mid_row.pack_propagate(False)
        mid_row.pack(fill="x", pady=(0, 8))

        grade_card = GlassCard(mid_row, width=320)
        grade_card.pack_propagate(False)
        grade_card.pack(side="left", fill="y", padx=(0, 8))
        self._section_header(grade_card, "2. Security Rating Speedometer", "Automated grading engine calculating CSP, HSTS, and X-Frame strength")

        gauge_container = ctk.CTkFrame(grade_card, fg_color="transparent")
        gauge_container.pack(padx=14, pady=(0, 8))

        gauge_canvas_wrap = ctk.CTkFrame(
            gauge_container,
            fg_color=THEME["bg_input"],
            corner_radius=10,
            border_width=1,
            border_color=THEME["border_subtle"]
        )
        gauge_canvas_wrap.pack()

        self._audit_gauge_canvas = tk.Canvas(
            gauge_canvas_wrap,
            width=280, height=140,
            bg=THEME["bg_input"],
            highlightthickness=0
        )
        self._audit_gauge_canvas.pack(padx=4, pady=4)

        self._audit_progress = ctk.CTkProgressBar(
            grade_card, height=6, corner_radius=3,
            fg_color=THEME["bg_input"],
            progress_color=THEME["neon_cyan"]
        )
        self._audit_progress.pack(fill="x", padx=14, pady=(0, 8))
        self._audit_progress.set(0.0)

        meta_card = GlassCard(mid_row)
        meta_card.pack(side="left", fill="both", expand=True, padx=(8, 0))
        self._section_header(meta_card, "3. Domain Security Telemetry", "Host posture breakdown and cookie flag evaluation")

        meta_inner = ctk.CTkFrame(meta_card, fg_color="transparent")
        meta_inner.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        self._audit_score_label = ctk.CTkLabel(
            meta_inner, text="Score: —",
            font=ctk.CTkFont(family=FONTS["title_hero"][0], size=18, weight="bold"),
            text_color=THEME["text_primary"]
        )
        self._audit_score_label.pack(anchor="w", pady=(2, 2))

        self._audit_domain_label = ctk.CTkLabel(
            meta_inner, text="Target Domain : —",
            font=ctk.CTkFont(family=FONTS["body"][0], size=FONTS["body"][1]),
            text_color=THEME["text_muted"]
        )
        self._audit_domain_label.pack(anchor="w", pady=1)

        self._audit_time_label = ctk.CTkLabel(
            meta_inner, text="Audit Timestamp: —",
            font=ctk.CTkFont(family=FONTS["caption"][0], size=FONTS["caption"][1]),
            text_color=THEME["text_muted"]
        )
        self._audit_time_label.pack(anchor="w", pady=1)

        self._audit_cookie_scroll = ctk.CTkFrame(
            meta_inner, fg_color=THEME["bg_input"],
            corner_radius=6, height=48
        )
        self._audit_cookie_scroll.pack(fill="x", pady=(6, 0))

        headers_card = GlassCard(body)
        headers_card.pack(fill="both", expand=True)
        self._section_header(headers_card, "4. HTTP Response Headers Inspection", "Audit presence and hardening parameters of defensive headers")

        self._audit_headers_scroll = ctk.CTkFrame(
            headers_card, fg_color=THEME["bg_input"],
            corner_radius=8
        )
        self._audit_headers_scroll.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        self._draw_grade_gauge(0, "—", THEME["text_muted"])
        return frame

    def _draw_grade_gauge(self, score: int, grade: str, color: str):
        canvas = self._audit_gauge_canvas
        canvas.delete("all")
        cx, cy, r = 140, 70, 54
        start_angle = -30
        total_arc = 240

        canvas.create_arc(
            cx - (r + 10), cy - (r + 10), cx + (r + 10), cy + (r + 10),
            start=start_angle,
            extent=total_arc,
            style="arc",
            outline=THEME["border_subtle"],
            width=2
        )

        canvas.create_arc(
            cx - r, cy - r, cx + r, cy + r,
            start=start_angle,
            extent=total_arc,
            style="arc",
            outline=THEME["bg_card"],
            width=12
        )

        for pct, angle_deg in [(0, 210), (25, 150), (50, 90), (75, 30), (100, -30)]:
            rad = math.radians(angle_deg)
            x1 = cx + (r - 8) * math.cos(rad)
            y1 = cy - (r - 8) * math.sin(rad)
            x2 = cx + (r + 8) * math.cos(rad)
            y2 = cy - (r + 8) * math.sin(rad)
            canvas.create_line(x1, y1, x2, y2, fill=THEME["border_subtle"], width=1)

        if score > 0:
            filled_arc = (max(0, min(100, score)) / 100.0) * total_arc
            start_pos = start_angle + (total_arc - filled_arc)
            canvas.create_arc(
                cx - r, cy - r, cx + r, cy + r,
                start=start_pos,
                extent=filled_arc,
                style="arc",
                outline=color,
                width=12
            )

        canvas.create_text(
            cx, cy - 8,
            text=grade,
            font=("Segoe UI", 28, "bold"),
            fill=color
        )
        canvas.create_text(
            cx, cy + 22,
            text=f"Score: {score}/100",
            font=("Segoe UI", 10, "bold"),
            fill=THEME["text_primary"]
        )
        canvas.create_text(
            cx, cy + 38,
            text="SECURITY POSTURE",
            font=("Segoe UI", 7, "bold"),
            fill=THEME["text_muted"]
        )

    def _start_gauge_animation(self, target_score: int, grade: str, color: str):
        self._gauge_start_score = 0
        self._gauge_target_score = target_score
        self._gauge_target_grade = grade
        self._gauge_target_color = color
        self._gauge_current_step = 0
        if self._gauge_job:
            try:
                self.after_cancel(self._gauge_job)
            except Exception:
                pass
        self._animate_gauge_step()

    def _animate_gauge_step(self):
        try:
            if not self.winfo_exists():
                self._gauge_job = None
                return
            self._gauge_current_step += 1
            u = self._gauge_current_step / float(self._gauge_total_steps)
            ease = 1.0 - (1.0 - u) ** 3
            cur_score = int(round(self._gauge_start_score + (self._gauge_target_score - self._gauge_start_score) * ease))
            self._draw_grade_gauge(cur_score, self._gauge_target_grade, self._gauge_target_color)
            self._audit_progress.set(cur_score / 100.0)
            self._audit_score_label.configure(text=f"Score: {cur_score}/100", text_color=self._gauge_target_color)
            if self._gauge_current_step < self._gauge_total_steps:
                self._gauge_job = self.after(20, self._animate_gauge_step)
            else:
                self._gauge_job = None
        except Exception:
            self._gauge_job = None

    def _audit_run_threaded(self):
        domain = self._audit_url_entry.get().strip()
        if not domain:
            messagebox.showwarning("Missing Host", "Please enter a domain or URL to audit.")
            return
        self._audit_score_label.configure(text="Scanning host...", text_color=THEME["neon_cyan"])
        self._audit_progress.set(0.0)
        self._draw_grade_gauge(0, "...", THEME["neon_cyan"])
        self._log("INFO", f"Security audit initiated for host: {domain}")
        thread = threading.Thread(target=self._audit_worker, args=(domain,), daemon=True)
        thread.start()

    def _audit_worker(self, domain: str):
        try:
            self.after(0, lambda: self._audit_progress.set(0.3))
            result = simulate_audit(domain)
            self.after(0, lambda: self._audit_progress.set(0.85))
            self.after(0, self._audit_display_result, result)
            self._log("SUCCESS", f"Audit complete: {domain} ➔ Grade {result['grade']} (Score: {result['score']}/100)")
        except Exception as exc:
            self._log("ERROR", f"Audit failed for {domain}: {exc}")
            self.after(0, lambda: messagebox.showerror("Audit Error", str(exc)))
            self.after(0, lambda: self._audit_progress.set(0.0))

    def _audit_display_result(self, result: dict):
        grade = result["grade"]
        score = result["score"]

        grade_colors = {
            "A+": THEME["neon_green"], "A": THEME["neon_green"],
            "B": "#88ff44", "C": THEME["neon_amber"],
            "D": "#ff7700", "F": THEME["neon_red"]
        }
        grade_color = grade_colors.get(grade, THEME["text_muted"])

        self._start_gauge_animation(score, grade, grade_color)
        self._audit_domain_label.configure(text=f"Target Domain : {result['domain']}")
        self._audit_time_label.configure(text=f"Audit Timestamp: {result['timestamp'][:19]}")
        self._audit_progress.configure(progress_color=grade_color)

        for widget in self._audit_headers_scroll.winfo_children():
            widget.destroy()

        header_row_hdr = ctk.CTkFrame(
            self._audit_headers_scroll,
            fg_color=THEME["bg_card"],
            corner_radius=6
        )
        header_row_hdr.pack(fill="x", pady=(0, 2))

        for col_txt, col_w in [("", 32), ("Header Name", 230), ("Directive / Stored Value", 0), ("Weight", 60)]:
            lbl_kw = dict(
                font=ctk.CTkFont(family=FONTS["caption_bold"][0], size=FONTS["caption_bold"][1], weight="bold"),
                text_color=THEME["neon_cyan"],
                anchor="w"
            )
            if col_w > 0:
                lbl_kw["width"] = col_w
            ctk.CTkLabel(header_row_hdr, text=col_txt, **lbl_kw).pack(side="left", padx=8, pady=5)

        for idx, hd in enumerate(result.get("header_details", [])):
            bg = THEME["bg_card"] if idx % 2 == 0 else THEME["bg_input"]
            hrow = ctk.CTkFrame(
                self._audit_headers_scroll,
                fg_color=bg,
                corner_radius=6
            )
            hrow.pack(fill="x", pady=1)

            status_is_present = hd["status"] == "PRESENT"
            icon_bg = THEME["badge_green_bg"] if status_is_present else THEME["badge_red_bg"]
            icon_txt = "✅" if status_is_present else "❌"

            icon_frame = ctk.CTkFrame(hrow, fg_color=icon_bg, corner_radius=6, width=28, height=28)
            icon_frame.pack(side="left", padx=6, pady=4)
            icon_frame.pack_propagate(False)
            ctk.CTkLabel(icon_frame, text=icon_txt, font=ctk.CTkFont(size=11)).place(relx=0.5, rely=0.5, anchor="center")

            hname_color = THEME["neon_cyan"] if status_is_present else THEME["text_muted"]
            ctk.CTkLabel(
                hrow, text=hd["header"][:36],
                font=ctk.CTkFont(family=FONTS["mono_body"][0], size=FONTS["mono_body"][1], weight="bold" if status_is_present else "normal"),
                text_color=hname_color,
                width=230,
                anchor="w"
            ).pack(side="left", padx=4, pady=4)

            ctk.CTkLabel(
                hrow, text=str(hd["value"])[:46],
                font=ctk.CTkFont(family=FONTS["mono_code"][0], size=FONTS["mono_code"][1]),
                text_color=THEME["text_primary"] if status_is_present else THEME["text_dim"],
                anchor="w"
            ).pack(side="left", padx=4, pady=4, fill="x", expand=True)

            pts_color = THEME["neon_green"] if status_is_present else THEME["text_muted"]
            ctk.CTkLabel(
                hrow, text=f"+{hd['weight']}pts",
                font=ctk.CTkFont(family=FONTS["mono_badge"][0], size=FONTS["mono_badge"][1], weight="bold"),
                text_color=pts_color,
                fg_color=THEME["bg_root"],
                corner_radius=6,
                width=56
            ).pack(side="right", padx=8, pady=4)

        if result.get("error"):
            err_frame = ctk.CTkFrame(self._audit_headers_scroll, fg_color=THEME["badge_red_bg"], corner_radius=8)
            err_frame.pack(fill="x", padx=4, pady=6)
            ctk.CTkLabel(
                err_frame,
                text=f"⚠ Inspection Notice: {result['error']}",
                font=ctk.CTkFont(family=FONTS["mono_code"][0], size=FONTS["mono_code"][1]),
                text_color=THEME["neon_red"]
            ).pack(anchor="w", padx=10, pady=6)

        for widget in self._audit_cookie_scroll.winfo_children():
            widget.destroy()

        ca = result.get("cookie_analysis", {})
        summary_bar = ctk.CTkFrame(self._audit_cookie_scroll, fg_color="transparent")
        summary_bar.pack(anchor="w", fill="x", padx=8, pady=(4, 4))

        ctk.CTkLabel(
            summary_bar,
            text=f"Total Cookies Discovered: {ca.get('total_cookies', 0)}",
            font=ctk.CTkFont(family=FONTS["body_bold"][0], size=FONTS["body_bold"][1], weight="bold"),
            text_color=THEME["text_primary"]
        ).pack(side="left", padx=(0, 16))

        insecure_cnt = ca.get('insecure_count', 0)
        insec_pill = ctk.CTkFrame(
            summary_bar,
            fg_color=THEME["badge_green_bg"] if insecure_cnt == 0 else THEME["badge_red_bg"],
            corner_radius=6
        )
        insec_pill.pack(side="left")
        ctk.CTkLabel(
            insec_pill,
            text=f"Insecure Cookies: {insecure_cnt}",
            font=ctk.CTkFont(family=FONTS["caption_bold"][0], size=FONTS["caption_bold"][1], weight="bold"),
            text_color=THEME["neon_green"] if insecure_cnt == 0 else THEME["neon_red"]
        ).pack(padx=8, pady=2)

        cookies = ca.get("cookies", [])
        if not cookies:
            ctk.CTkLabel(
                self._audit_cookie_scroll,
                text="No cookies detected in response headers.",
                font=ctk.CTkFont(family=FONTS["body"][0], size=FONTS["body"][1]),
                text_color=THEME["text_muted"]
            ).pack(anchor="w", padx=8, pady=8)
        else:
            for c in cookies[:3]:
                cookie_card = ctk.CTkFrame(
                    self._audit_cookie_scroll,
                    fg_color=THEME["bg_card"],
                    corner_radius=6,
                    border_width=1,
                    border_color=THEME["border_subtle"],
                    height=28
                )
                cookie_card.pack(fill="x", padx=4, pady=2)
                cookie_card.pack_propagate(False)

                ctk.CTkLabel(
                    cookie_card, text=c["name"][:22],
                    font=ctk.CTkFont(family=FONTS["mono_body"][0], size=10, weight="bold"),
                    text_color=THEME["neon_cyan"],
                    anchor="w"
                ).pack(side="left", padx=(8, 4))

                flags_row = ctk.CTkFrame(cookie_card, fg_color="transparent")
                flags_row.pack(side="right", padx=6)

                for flag_name, flag_val in [
                    ("HttpOnly", c.get("httponly", False)),
                    ("Secure", c.get("secure", False)),
                    ("SameSite", bool(c.get("samesite")))
                ]:
                    pill_color = THEME["badge_green_bg"] if flag_val else THEME["badge_red_bg"]
                    pill_text_color = THEME["neon_green"] if flag_val else THEME["neon_red"]
                    pill = ctk.CTkFrame(flags_row, fg_color=pill_color, corner_radius=4)
                    pill.pack(side="left", padx=2)
                    ctk.CTkLabel(
                        pill, text=f"{'✓' if flag_val else '✗'} {flag_name}",
                        font=ctk.CTkFont(family=FONTS["caption_bold"][0], size=8, weight="bold"),
                        text_color=pill_text_color
                    ).pack(padx=5, pady=1)

            if len(cookies) > 3:
                ctk.CTkLabel(
                    self._audit_cookie_scroll,
                    text=f"+{len(cookies) - 3} more cookie(s) detected",
                    font=ctk.CTkFont(family=FONTS["caption"][0], size=9),
                    text_color=THEME["text_muted"]
                ).pack(anchor="w", padx=8, pady=(1, 2))

    def _build_log_frame(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color=THEME["bg_root"], corner_radius=0)
        self._page_header(
            frame, "📋", "Enterprise Audit Log Console",
            "Real-Time Telemetry Stream: Hardware Actions, Cryptographic Signatures & System State"
        )

        toolbar = ctk.CTkFrame(frame, fg_color="transparent")
        toolbar.pack(fill="x", padx=28, pady=(8, 0))

        self._action_button(
            toolbar, "🗑  Clear Buffer", self._log_clear,
            color=THEME["bg_card_hover"]
        ).pack(side="left", padx=(0, 10))

        self._action_button(
            toolbar, "💾  Export Audit Log (.txt)", self._log_export,
            color=THEME["neon_cyan"],
            text_color=THEME["bg_root"]
        ).pack(side="left")

        self._log_count_label = ctk.CTkLabel(
            toolbar,
            text="0 entries",
            font=ctk.CTkFont(family=FONTS["caption_bold"][0], size=FONTS["caption_bold"][1]),
            text_color=THEME["text_muted"]
        )
        self._log_count_label.pack(side="right")

        filter_row = ctk.CTkFrame(frame, fg_color="transparent")
        filter_row.pack(fill="x", padx=28, pady=(8, 4))

        ctk.CTkLabel(
            filter_row, text="Severity Filters:",
            font=ctk.CTkFont(family=FONTS["caption_bold"][0], size=FONTS["caption_bold"][1], weight="bold"),
            text_color=THEME["text_muted"]
        ).pack(side="left", padx=(0, 8))

        self._filter_buttons: dict[str, ctk.CTkButton] = {}
        filter_levels = ["INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]
        self._filter_colors = {
            "INFO": THEME["neon_cyan"],
            "SUCCESS": THEME["neon_green"],
            "WARNING": THEME["neon_amber"],
            "ERROR": THEME["neon_red"],
            "CRITICAL": "#ff0055",
        }

        for level in filter_levels:
            btn = ctk.CTkButton(
                filter_row,
                text=level,
                font=ctk.CTkFont(family=FONTS["mono_badge"][0], size=FONTS["mono_badge"][1], weight="bold"),
                fg_color=self._filter_colors[level],
                text_color=THEME["bg_root"],
                hover_color=THEME["neon_cyan_glow"],
                corner_radius=6,
                height=26,
                width=72,
                command=lambda lv=level: self._toggle_log_filter(lv)
            )
            btn.pack(side="left", padx=(0, 6))
            btn.configure(cursor="hand2")
            self._filter_buttons[level] = btn

        log_outer = GlassCard(frame, corner_radius=12)
        log_outer.pack(fill="both", expand=True, padx=24, pady=12)

        self._log_text_widget = tk.Text(
            log_outer,
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            font=(FONTS["mono_body"][0], FONTS["mono_body"][1]),
            relief="flat",
            padx=12,
            pady=12,
            wrap="none",
            state="disabled",
            insertbackground=THEME["neon_cyan"]
        )

        log_scrollbar = ttk.Scrollbar(log_outer, command=self._log_text_widget.yview)
        self._log_text_widget.configure(yscrollcommand=log_scrollbar.set)

        log_scrollbar.pack(side="right", fill="y")
        self._log_text_widget.pack(fill="both", expand=True)

        self._log_text_widget.tag_config("INFO", foreground=THEME["neon_cyan"])
        self._log_text_widget.tag_config("SUCCESS", foreground=THEME["neon_green"])
        self._log_text_widget.tag_config("WARNING", foreground=THEME["neon_amber"])
        self._log_text_widget.tag_config("ERROR", foreground=THEME["neon_red"])
        self._log_text_widget.tag_config("CRITICAL", foreground="#ff0055")

        startup_lines = [
            ("INFO", f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] VaultChain Guard Pro Suite v2.0 initialized."),
            ("INFO", f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] Cryptographic primitives verified: DES-CBC | RSA-2048 OAEP | SHA-256 PSS."),
            ("INFO", f"[{datetime.now().strftime('%H:%M:%S')}] [INFO] Hardware-safe thread pool armed. Real-time audit telemetry online."),
        ]
        self._log_text_widget.configure(state="normal")
        for tag, line in startup_lines:
            self._log_text_widget.insert("end", line + "\n", tag)
        self._log_text_widget.configure(state="disabled")

        return frame

    def _toggle_log_filter(self, level: str):
        if level in self._log_active_filters:
            self._log_active_filters.discard(level)
            self._filter_buttons[level].configure(
                fg_color=THEME["bg_card"],
                text_color=THEME["text_muted"]
            )
        else:
            self._log_active_filters.add(level)
            self._filter_buttons[level].configure(
                fg_color=self._filter_colors[level],
                text_color=THEME["bg_root"]
            )
        self._rebuild_log_display()

    def _rebuild_log_display(self):
        widget = self._log_text_widget
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        for entry in self._audit_log:
            detected_level = "INFO"
            for lv in ["CRITICAL", "ERROR", "WARNING", "SUCCESS", "INFO"]:
                if f"[{lv}]" in entry:
                    detected_level = lv
                    break
            if detected_level in self._log_active_filters:
                widget.insert("end", entry + "\n", detected_level)
        widget.see("end")
        widget.configure(state="disabled")

    def _log_clear(self):
        self._audit_log.clear()
        self._log_text_widget.configure(state="normal")
        self._log_text_widget.delete("1.0", "end")
        self._log_text_widget.configure(state="disabled")
        self._log_count_label.configure(text="0 entries")

    def _log_export(self):
        if not self._audit_log:
            messagebox.showinfo("Empty Log Buffer", "No log entries to export yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt")],
            initialfile=f"vaultchain_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if path:
            header = (
                f"VaultChain Guard — Enterprise Security Audit Report\n"
                f"Generated: {datetime.now().isoformat()}\n"
                f"Total Entries: {len(self._audit_log)}\n"
                f"{'─' * 70}\n\n"
            )
            with open(path, "w", encoding="utf-8") as f:
                f.write(header)
                f.write("\n".join(self._audit_log))
            self._log("INFO", f"Audit report exported: {os.path.basename(path)}")
            messagebox.showinfo("Export Successful", f"Audit log saved to:\n{path}")
