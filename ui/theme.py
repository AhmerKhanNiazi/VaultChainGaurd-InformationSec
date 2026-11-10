import customtkinter as ctk

THEME = {
    "bg_root": "#050813",
    "bg_sidebar": "#080e1d",
    "bg_card": "#0c152a",
    "bg_card_hover": "#111f3c",
    "bg_input": "#070c18",
    "bg_inner_box": "#0a1122",
    
    "border_subtle": "#172646",
    "border_glow": "#0284c7",
    "border_cyan": "#00f0ff",
    "border_active": "#38bdf8",
    
    "neon_cyan": "#00f0ff",
    "neon_cyan_glow": "#38bdf8",
    "neon_green": "#00ff9d",
    "neon_red": "#ff3366",
    "neon_amber": "#fbbf24",
    "neon_purple": "#a855f7",
    
    "text_primary": "#f8fafc",
    "text_secondary": "#94a3b8",
    "text_muted": "#64748b",
    "text_dim": "#475569",
    
    "badge_green_bg": "#063d2e",
    "badge_red_bg": "#450a1a",
    "badge_cyan_bg": "#072b3b",
}

FONTS = {
    "title_hero": ("Segoe UI", 22, "bold"),
    "title_section": ("Segoe UI", 15, "bold"),
    "title_card": ("Segoe UI", 13, "bold"),
    "body": ("Segoe UI", 12),
    "body_bold": ("Segoe UI", 12, "bold"),
    "caption": ("Segoe UI", 10),
    "caption_bold": ("Segoe UI", 10, "bold"),
    "mono_body": ("Consolas", 11),
    "mono_code": ("Consolas", 10),
    "mono_badge": ("Consolas", 9, "bold"),
}

def hex_to_rgb(hex_code: str) -> tuple[int, int, int]:
    clean = hex_code.lstrip("#")
    if len(clean) == 3:
        clean = "".join([c * 2 for c in clean])
    return int(clean[0:2], 16), int(clean[2:4], 16), int(clean[4:6], 16)

def rgb_to_hex(r: int, g: int, b: int) -> str:
    r_val = max(0, min(255, int(round(r))))
    g_val = max(0, min(255, int(round(g))))
    b_val = max(0, min(255, int(round(b))))
    return f"#{r_val:02x}{g_val:02x}{b_val:02x}"

def interpolate_color(c1: str, c2: str, t: float) -> str:
    clamped_t = max(0.0, min(1.0, t))
    r1, g1, b1 = hex_to_rgb(c1)
    r2, g2, b2 = hex_to_rgb(c2)
    return rgb_to_hex(
        r1 + (r2 - r1) * clamped_t,
        g1 + (g2 - g1) * clamped_t,
        b1 + (b2 - b1) * clamped_t
    )
