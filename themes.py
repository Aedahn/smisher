"""Application themes and styling."""

LIGHT_THEME = {
    "name": "light",
    "bg": "#f4f4f7",         # Soft neutral gray-blue background
    "surface": "#ffffff",    # Clean white
    "surface_alt": "#e9e9eb",# Soft light gray for items/stat cards
    "border": "#d1d1d6",     # Clean borders
    "text": "#1c1c1e",       # Dark gray text (highly readable, non-glaring)
    "text_muted": "#68686e", # Muted gray text
    "accent": "#5856d6",     # Royal indigo accent
    "accent_hover": "#403ebd",
    "accent_soft": "#e5e5ea",# Soft light highlight tint
    "success": "#0f766e",    # Teal 700
    "success_bg": "#ccfbf1",
    "danger": "#b91c1c",     # Red 700
    "danger_bg": "#fee2e2",
    "warning": "#b45309",    # Amber 700
    "neutral": "#8e8e93",    # System gray
    "neutral_bg": "#e5e5ea", # Selection gray
    "sidebar": "#1c1c1e",
    "sidebar_text": "#e5e5ea",
    "sidebar_active": "#2c2c2e",
    "shadow": "rgba(0, 0, 0, 0.05)",
}

DARK_THEME = {
    "name": "dark",
    "bg": "#121214",         # Clean neutral dark gray background
    "surface": "#1a1a1e",    # Slightly lighter dark gray panels
    "surface_alt": "#222227",# Alt gray surface for items
    "border": "#2e2e35",     # Softer clean borders
    "text": "#e3e3e6",       # Clean off-white text
    "text_muted": "#8e8e93", # System gray for muted text
    "accent": "#5856d6",     # Royal indigo accent
    "accent_hover": "#7d7aff",
    "accent_soft": "#1c1c2e",# Dark indigo tint
    "success": "#34d399",    # Emerald 400
    "success_bg": "#064e3b",
    "danger": "#fb7185",     # Rose 400
    "danger_bg": "#4c0519",
    "warning": "#fbbf24",    # Amber 400
    "neutral": "#636366",    # Slate gray
    "neutral_bg": "#2c2c35", # Selection gray
    "sidebar": "#09090b",
    "sidebar_text": "#e3e3e6",
    "sidebar_active": "#1a1a1e",
    "shadow": "rgba(0, 0, 0, 0.4)",
}


def build_stylesheet(theme: dict[str, str]) -> str:
    t = theme
    return f"""
    QMainWindow, QWidget {{
        background-color: {t['bg']};
        color: {t['text']};
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        font-size: 13px;
    }}

    QMenuBar {{
        background: {t['surface']};
        border-bottom: 1px solid {t['border']};
        padding: 6px;
    }}
    QMenuBar::item:selected {{
        background: {t['surface_alt']};
        border-radius: 6px;
    }}
    QMenu {{
        background: {t['surface']};
        border: 1px solid {t['border']};
        padding: 6px;
        border-radius: 8px;
    }}
    QMenu::item:selected {{
        background: {t['accent']};
        color: white;
        border-radius: 4px;
    }}

    QToolBar {{
        background: {t['surface']};
        border-bottom: 1px solid {t['border']};
        spacing: 10px;
        padding: 8px 14px;
    }}

    /* Top bar panel styling */
    QFrame#topBar {{
        background: {t['surface']};
        border-bottom: 1px solid {t['border']};
    }}

    QLabel#appTitle {{
        color: {t['text']};
        font-size: 20px;
        font-weight: 800;
        letter-spacing: -0.5px;
    }}
    

    /* Global Scrollbar Design */
    QScrollBar:vertical {{
        border: none;
        background: transparent;
        width: 10px;
        margin: 0px;
    }}
    QScrollBar::handle:vertical {{
        background: {t['border']};
        min-height: 20px;
        border-radius: 5px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {t['accent']};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0px;
    }}
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
        background: none;
    }}

    QScrollBar:horizontal {{
        border: none;
        background: transparent;
        height: 10px;
        margin: 0px;
    }}
    QScrollBar::handle:horizontal {{
        background: {t['border']};
        min-width: 20px;
        border-radius: 5px;
    }}
    QScrollBar::handle:horizontal:hover {{
        background: {t['accent']};
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0px;
    }}
    QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
        background: none;
    }}

    /* Button Styling */
    QPushButton {{
        background: {t['surface']};
        color: {t['text']};
        border: 1px solid {t['border']};
        border-radius: 8px;
        padding: 8px 16px;
        font-weight: 600;
        font-size: 12px;
    }}
    QPushButton:hover {{
        background: {t['surface_alt']};
        border-color: {t['accent']};
    }}
    QPushButton:pressed {{
        background: {t['border']};
    }}
    QPushButton:disabled {{
        color: {t['text_muted']};
        background: {t['surface_alt']};
        border-color: {t['border']};
    }}

    QPushButton#primaryBtn {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {t['accent']}, stop:1 {t['accent_hover']});
        color: white;
        border: none;
    }}
    QPushButton#primaryBtn:hover {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {t['accent_hover']}, stop:1 {t['accent']});
    }}

    QPushButton#dangerBtn {{
        background: {t['danger']};
        color: white;
        border: none;
    }}
    QPushButton#dangerBtn:hover {{
        opacity: 0.9;
    }}

    QPushButton#successBtn {{
        background: {t['success']};
        color: white;
        border: none;
    }}
    QPushButton#successBtn:hover {{
        opacity: 0.9;
    }}

    QPushButton#topFolderBtn {{
        background: {t['surface_alt']};
        color: {t['text']};
        border: 1px solid {t['border']};
        border-radius: 8px;
        padding: 8px 16px;
        font-weight: 700;
    }}
    QPushButton#topFolderBtn:hover {{
        border-color: {t['accent']};
        background: {t['surface']};
    }}
    QPushButton#topFolderBtn[active="true"] {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {t['accent']}, stop:1 {t['accent_hover']});
        color: white;
        border: none;
    }}

    /* Tool button / toggles */
    QToolButton {{
        background: {t['surface_alt']};
        color: {t['text']};
        border: 1px solid {t['border']};
        border-radius: 8px;
        padding: 6px 12px;
        font-weight: 600;
    }}
    QToolButton:hover {{
        border-color: {t['accent']};
        background: {t['accent_soft']};
        color: {t['accent']};
    }}

    /* QListWidget Styling */
    QListWidget {{
        background: {t['surface']};
        border: 1px solid {t['border']};
        border-radius: 12px;
        outline: none;
        padding: 6px;
    }}
    QListWidget::item {{
        background: transparent;
        border: 1px solid transparent;
        border-left: 4px solid transparent;
        border-radius: 6px;
        margin: 2px 4px;
        padding: 4px 0px;
    }}
    QListWidget::item:hover:!selected {{
        background: {t['surface_alt']};
    }}
    QListWidget::item:selected {{
        background: {t['neutral_bg']};
        border-left: 4px solid {t['accent']};
        color: {t['text']};
    }}

    /* Email list specific label styles (unselected) */
    QLabel#emailSubject {{
        font-weight: 700;
        font-size: 13px;
        color: {t['text']};
    }}
    QLabel#emailSender, QLabel#emailMeta {{
        color: {t['text_muted']};
        font-size: 11px;
    }}

    /* QTextBrowser (Metadata, Body viewer) Styling */
    QTextBrowser {{
        background: {t['surface']};
        border: 1px solid {t['border']};
        border-radius: 12px;
        padding: 14px;
        selection-background-color: {t['accent']};
        selection-color: white;
        font-size: 13px;
        line-height: 1.5;
    }}

    QTextBrowser a {{
        color: {t['accent']};
        text-decoration: underline;
    }}
    QTextBrowser a:hover {{
        color: {t['accent_hover']};
    }}

    QScrollArea {{
        border: none;
        background: transparent;
    }}

    QProgressBar {{
        border: 1px solid {t['border']};
        border-radius: 8px;
        background: {t['surface_alt']};
        text-align: center;
        color: {t['text']};
        font-weight: 600;
        height: 14px;
    }}
    QProgressBar::chunk {{
        border-radius: 7px;
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {t['accent']}, stop:1 {t['accent_hover']});
    }}

    /* Panel Headers and subheaders styling */
    QLabel#panelHeader {{
        font-size: 16px;
        font-weight: 800;
        color: {t['text']};
        letter-spacing: -0.3px;
        margin-bottom: 6px;
        margin-top: 4px;
    }}

    QLabel#sectionSubHeader {{
        font-size: 11px;
        font-weight: 700;
        color: {t['text_muted']};
        text-transform: uppercase;
        letter-spacing: 0.8px;
        margin-top: 8px;
        margin-bottom: 4px;
    }}

    /* Card Layouts */
    QFrame#card {{
        background: {t['surface']};
        border: 1px solid {t['border']};
        border-radius: 12px;
    }}

    /* Dashboard Stat Cards */
    QFrame#statCard {{
        background: {t['surface_alt']};
        border: 1px solid {t['border']};
        border-radius: 10px;
    }}
    QFrame#statCard:hover {{
        border-color: {t['accent']};
        background: {t['surface']};
    }}
    QLabel#statTitle {{
        color: {t['text_muted']};
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}
    QLabel#statValue {{
        color: {t['text']};
        font-size: 16px;
        font-weight: 800;
    }}

    /* AgentCard Styling */
    QFrame#agentCard {{
        background: {t['surface_alt']};
        border: 1px solid {t['border']};
        border-radius: 12px;
    }}
    QFrame#agentCard:hover {{
        border-color: {t['accent']};
        background: {t['surface']};
    }}
    QLabel#agentTitle {{
        font-weight: 800;
        font-size: 13px;
        color: {t['text']};
    }}
    QLabel#agentVerdict {{
        font-weight: 800;
        font-size: 11px;
        border-radius: 6px;
        padding: 2px 8px;
    }}
    QLabel#agentVerdict[verdict="phishing"] {{
        background: {t['danger_bg']};
        color: {t['danger']};
        border: 1px solid {t['danger']};
    }}
    QLabel#agentVerdict[verdict="legitimate"] {{
        background: {t['success_bg']};
        color: {t['success']};
        border: 1px solid {t['success']};
    }}
    QLabel#agentVerdict[verdict="unknown"] {{
        background: {t['neutral_bg']};
        color: {t['neutral']};
        border: 1px solid {t['border']};
    }}
    QLabel#agentConfidence {{
        font-weight: 700;
        font-size: 11px;
        color: {t['text_muted']};
    }}
    QLabel#agentReason {{
        font-size: 12px;
        color: {t['text_muted']};
        line-height: 1.4;
    }}

    /* Groupbox structure */
    QGroupBox {{
        font-weight: 700;
        border: 1px solid {t['border']};
        border-radius: 12px;
        margin-top: 14px;
        padding-top: 20px;
        background: {t['surface']};
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 14px;
        padding: 0 8px;
        color: {t['text']};
    }}

    QSplitter::handle {{
        background: {t['border']};
    }}
    QSplitter::handle:horizontal {{
        width: 3px;
    }}

    QLabel#detailLabel {{
        color: {t['text_muted']};
        font-weight: 600;
        font-size: 11px;
    }}

    QStatusBar {{
        background: {t['surface']};
        border-top: 1px solid {t['border']};
        color: {t['text_muted']};
        font-size: 11px;
        padding: 4px;
    }}
    """
