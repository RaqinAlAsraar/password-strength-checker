"""
PyQt6 Styling and Cyber-Security Theme Definitions.
"""

# Color Palette Constants
BG_DARK = "#0b0f19"
BG_CARD = "#131b2e"
BG_INPUT = "#1e293b"
BG_HOVER = "#24324d"
BORDER_DEFAULT = "#2e3e5c"
BORDER_FOCUS = "#06b6d4"

TEXT_PRIMARY = "#f8fafc"
TEXT_MUTED = "#94a3b8"
TEXT_DIM = "#64748b"

COLOR_CRITICAL = "#ef4444"
COLOR_WARNING = "#f97316"
COLOR_MODERATE = "#eab308"
COLOR_STRONG = "#22c55e"
COLOR_EXCELLENT = "#06b6d4"


def get_application_stylesheet() -> str:
    """Return master stylesheet for PyQt6 application."""
    return f"""
    QMainWindow, QWidget {{
        background-color: {BG_DARK};
        color: {TEXT_PRIMARY};
        font-family: 'Segoe UI', 'Ubuntu', 'Roboto', 'Helvetica Neue', sans-serif;
        font-size: 13px;
    }}

    QTabWidget::pane {{
        border: 1px solid {BORDER_DEFAULT};
        border-radius: 8px;
        background-color: {BG_CARD};
        padding: 6px;
    }}

    QTabBar::tab {{
        background: #111827;
        color: {TEXT_MUTED};
        padding: 10px 20px;
        margin-right: 4px;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        font-weight: 600;
    }}

    QTabBar::tab:selected {{
        background: {BG_CARD};
        color: {BORDER_FOCUS};
        border-bottom: 2px solid {BORDER_FOCUS};
    }}

    QTabBar::tab:hover {{
        background: {BG_HOVER};
        color: {TEXT_PRIMARY};
    }}

    QLineEdit {{
        background-color: {BG_INPUT};
        border: 1px solid {BORDER_DEFAULT};
        border-radius: 6px;
        padding: 10px 14px;
        color: {TEXT_PRIMARY};
        font-family: 'Consolas', 'DejaVu Sans Mono', 'Courier New', monospace;
        font-size: 15px;
        selection-background-color: #0284c7;
    }}

    QLineEdit:focus {{
        border: 2px solid {BORDER_FOCUS};
        background-color: #172554;
    }}

    QPushButton {{
        background-color: #1e293b;
        border: 1px solid {BORDER_DEFAULT};
        border-radius: 6px;
        color: {TEXT_PRIMARY};
        padding: 8px 16px;
        font-weight: 600;
    }}

    QPushButton:hover {{
        background-color: {BG_HOVER};
        border-color: {BORDER_FOCUS};
    }}

    QPushButton:pressed {{
        background-color: #0f172a;
    }}

    QPushButton#primaryButton {{
        background-color: #0284c7;
        color: #ffffff;
        border: 1px solid #38bdf8;
    }}

    QPushButton#primaryButton:hover {{
        background-color: #0369a1;
    }}

    QProgressBar {{
        background-color: #1e293b;
        border: 1px solid {BORDER_DEFAULT};
        border-radius: 6px;
        height: 18px;
        text-align: center;
        font-weight: bold;
        color: #ffffff;
    }}

    QProgressBar::chunk {{
        border-radius: 5px;
        background-color: #06b6d4;
    }}

    QGroupBox {{
        background-color: {BG_CARD};
        border: 1px solid {BORDER_DEFAULT};
        border-radius: 8px;
        margin-top: 14px;
        padding: 14px;
        font-weight: bold;
        color: {BORDER_FOCUS};
    }}

    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 14px;
        padding: 0 6px;
        background-color: {BG_CARD};
    }}

    QScrollArea {{
        border: none;
        background-color: transparent;
    }}

    QScrollBar:vertical {{
        background: #0f172a;
        width: 8px;
        border-radius: 4px;
    }}

    QScrollBar::handle:vertical {{
        background: #334155;
        border-radius: 4px;
        min-height: 20px;
    }}

    QScrollBar::handle:vertical:hover {{
        background: #475569;
    }}

    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0px;
    }}

    QLabel {{
        color: {TEXT_PRIMARY};
    }}

    QCheckBox {{
        color: {TEXT_PRIMARY};
        spacing: 8px;
        font-weight: 500;
    }}

    QCheckBox::indicator {{
        width: 18px;
        height: 18px;
        border: 1px solid {BORDER_DEFAULT};
        border-radius: 4px;
        background-color: {BG_INPUT};
    }}

    QCheckBox::indicator:checked {{
        background-color: {BORDER_FOCUS};
        border-color: {BORDER_FOCUS};
    }}

    QSlider::groove:horizontal {{
        height: 6px;
        background: #1e293b;
        border-radius: 3px;
    }}

    QSlider::sub-page:horizontal {{
        background: {BORDER_FOCUS};
        border-radius: 3px;
    }}

    QSlider::handle:horizontal {{
        background: #ffffff;
        border: 2px solid {BORDER_FOCUS};
        width: 16px;
        margin-top: -5px;
        margin-bottom: -5px;
        border-radius: 8px;
    }}

    QSpinBox {{
        background-color: {BG_INPUT};
        border: 1px solid {BORDER_DEFAULT};
        border-radius: 6px;
        padding: 4px 8px;
        color: {TEXT_PRIMARY};
        font-weight: bold;
    }}
    """
