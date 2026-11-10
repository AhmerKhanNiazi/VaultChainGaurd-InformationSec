import tkinter as tk
import math
import customtkinter as ctk
from ui.theme import THEME, FONTS, interpolate_color

class GlassCard(ctk.CTkFrame):
    def __init__(self, master, hover_glow=True, **kwargs):
        border_c = kwargs.pop("border_color", THEME["border_subtle"])
        fg_c = kwargs.pop("fg_color", THEME["bg_card"])
        corner_r = kwargs.pop("corner_radius", 16)
        border_w = kwargs.pop("border_width", 1)
        
        super().__init__(
            master,
            fg_color=fg_c,
            border_color=border_c,
            corner_radius=corner_r,
            border_width=border_w,
            **kwargs
        )
        self.default_border = border_c
        self.default_fg = fg_c
        self.hover_border = THEME["neon_cyan_glow"]
        self.hover_fg = THEME["bg_card_hover"]
        if hover_glow:
            self.bind("<Enter>", self._on_enter, add="+")
            self.bind("<Leave>", self._on_leave, add="+")

    def _on_enter(self, event=None):
        try:
            self.configure(border_color=self.hover_border, fg_color=self.hover_fg)
        except Exception:
            return

    def _on_leave(self, event=None):
        try:
            self.configure(border_color=self.default_border, fg_color=self.default_fg)
        except Exception:
            return

class NavPill(ctk.CTkFrame):
    def __init__(self, master, icon: str, label: str, command=None, **kwargs):
        super().__init__(
            master,
            height=42,
            corner_radius=8,
            fg_color="transparent",
            border_width=0,
            cursor="hand2",
            **kwargs
        )
        self.grid_propagate(False)
        self.command = command
        self.is_active = False

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)

        self.icon_lbl = ctk.CTkLabel(
            self, text=icon, width=32,
            font=ctk.CTkFont(size=15),
            text_color=THEME["text_secondary"]
        )
        self.icon_lbl.grid(row=0, column=0, padx=(14, 8), sticky="w")

        self.text_lbl = ctk.CTkLabel(
            self, text=label,
            font=ctk.CTkFont(family=FONTS["body_bold"][0], size=12, weight="bold"),
            text_color=THEME["text_secondary"],
            anchor="w"
        )
        self.text_lbl.grid(row=0, column=1, sticky="w")

        for w in (self, self.icon_lbl, self.text_lbl):
            w.bind("<Button-1>", self._on_click)
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)

    def set_active(self, active: bool):
        self.is_active = active
        if active:
            self.configure(
                fg_color="#0e2246",
                border_color=THEME["neon_cyan"],
                border_width=1
            )
            self.icon_lbl.configure(text_color=THEME["neon_cyan"])
            self.text_lbl.configure(text_color=THEME["neon_cyan"])
        else:
            self.configure(
                fg_color="transparent",
                border_width=0
            )
            self.icon_lbl.configure(text_color=THEME["text_secondary"])
            self.text_lbl.configure(text_color=THEME["text_secondary"])

    def _on_enter(self, event=None):
        if not self.is_active:
            self.configure(fg_color="#0e172a")
            self.icon_lbl.configure(text_color=THEME["text_primary"])
            self.text_lbl.configure(text_color=THEME["text_primary"])

    def _on_leave(self, event=None):
        if not self.is_active:
            self.configure(fg_color="transparent")
            self.icon_lbl.configure(text_color=THEME["text_secondary"])
            self.text_lbl.configure(text_color=THEME["text_secondary"])

    def _on_click(self, event=None):
        if self.command:
            self.command()

class PulsingBeacon(tk.Canvas):
    def __init__(self, master, size=22, **kwargs):
        super().__init__(
            master,
            width=size,
            height=size,
            bg=kwargs.pop("bg", THEME["bg_sidebar"]),
            highlightthickness=0,
            **kwargs
        )
        self.size = size
        self.phase = 0.0
        self.job = None
        self.active = True
        self._animate()

    def _animate(self):
        if not self.active:
            return
        try:
            if not self.winfo_exists():
                return
            self.phase += 0.09
            factor = (1.0 + math.sin(self.phase)) / 2.0
            halo_color = interpolate_color("#052e42", "#0284c7", factor)
            core_color = interpolate_color("#38bdf8", "#00f0ff", factor)
            
            self.delete("all")
            cx, cy = self.size / 2.0, self.size / 2.0
            r_halo = (self.size / 3.0) + (self.size / 6.0) * factor
            self.create_oval(cx - r_halo, cy - r_halo, cx + r_halo, cy + r_halo, fill=halo_color, outline="")
            self.create_oval(cx - 3.5, cy - 3.5, cx + 3.5, cy + 3.5, fill=core_color, outline="")
            self.job = self.after(50, self._animate)
        except Exception:
            self.active = False

    def stop(self):
        self.active = False
        if self.job:
            try:
                self.after_cancel(self.job)
            except Exception:
                pass
            self.job = None

class LiveCyberWaveform(tk.Canvas):
    def __init__(self, master, width=280, height=36, **kwargs):
        super().__init__(
            master,
            width=width,
            height=height,
            bg=kwargs.pop("bg", THEME["bg_input"]),
            highlightthickness=0,
            **kwargs
        )
        self.w = width
        self.h = height
        self.phase = 0.0
        self.active = True
        self.job = None
        self._draw_wave()

    def _draw_wave(self):
        if not self.active:
            return
        try:
            if not self.winfo_exists():
                return
            self.phase += 0.12
            self.delete("all")
            cy = self.h / 2.0
            points = []
            for x in range(0, self.w, 4):
                sine1 = math.sin((x * 0.04) + self.phase)
                sine2 = math.cos((x * 0.08) - (self.phase * 1.5))
                y = cy + (sine1 * (self.h * 0.28)) + (sine2 * (self.h * 0.14))
                points.append((x, y))
            
            for i in range(len(points) - 1):
                x1, y1 = points[i]
                x2, y2 = points[i+1]
                t = i / max(1, len(points))
                c = interpolate_color(THEME["neon_cyan"], THEME["neon_green"], t)
                self.create_line(x1, y1, x2, y2, fill=c, width=2)
            
            self.job = self.after(50, self._draw_wave)
        except Exception:
            self.active = False

    def stop(self):
        self.active = False
        if self.job:
            try:
                self.after_cancel(self.job)
            except Exception:
                pass
            self.job = None

class RadarScanner(tk.Canvas):
    def __init__(self, master, size=110, **kwargs):
        super().__init__(
            master,
            width=size,
            height=size,
            bg=kwargs.pop("bg", THEME["bg_card"]),
            highlightthickness=0,
            **kwargs
        )
        self.size = size
        self.angle = 0.0
        self.active = True
        self.job = None
        self._targets = [(0.6, 45), (0.45, 140), (0.75, 275)]
        self._animate()

    def _animate(self):
        if not self.active:
            return
        try:
            if not self.winfo_exists():
                return
            self.angle = (self.angle + 4.5) % 360.0
            self.delete("all")
            cx, cy = self.size / 2.0, self.size / 2.0
            r = (self.size / 2.0) - 6

            for ring_r in [r * 0.35, r * 0.7, r]:
                self.create_oval(cx - ring_r, cy - ring_r, cx + ring_r, cy + ring_r, outline=THEME["border_subtle"], width=1)
            self.create_line(cx - r, cy, cx + r, cy, fill=THEME["border_subtle"], width=1)
            self.create_line(cx, cy - r, cx, cy + r, fill=THEME["border_subtle"], width=1)

            rad = math.radians(self.angle)
            sweep_x = cx + r * math.cos(rad)
            sweep_y = cy + r * math.sin(rad)

            self.create_arc(
                cx - r, cy - r, cx + r, cy + r,
                start=-self.angle,
                extent=45,
                fill=THEME["badge_cyan_bg"],
                outline=""
            )
            self.create_line(cx, cy, sweep_x, sweep_y, fill=THEME["neon_cyan"], width=2)
            self.create_oval(cx - 3, cy - 3, cx + 3, cy + 3, fill=THEME["neon_cyan"], outline="")

            for factor, t_deg in self._targets:
                diff = (self.angle - t_deg) % 360
                alpha = max(0.0, 1.0 - (diff / 65.0)) if diff < 65.0 else 0.0
                t_rad = math.radians(t_deg)
                tx = cx + (r * factor) * math.cos(t_rad)
                ty = cy + (r * factor) * math.sin(t_rad)
                dot_c = THEME["neon_green"] if alpha > 0.4 else THEME["border_subtle"]
                dot_r = 3 if alpha > 0.4 else 2
                self.create_oval(tx - dot_r, ty - dot_r, tx + dot_r, ty + dot_r, fill=dot_c, outline="")

            self.job = self.after(50, self._animate)
        except Exception:
            self.active = False

    def stop(self):
        self.active = False
        if self.job:
            try:
                self.after_cancel(self.job)
            except Exception:
                pass
            self.job = None
