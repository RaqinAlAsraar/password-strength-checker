#!/usr/bin/env python3
"""
Main Entry Point for CodeNova Password Strength Checker & Entropy Auditor.

Modes:
- Default: Modern clean desktop GUI (Chromium app mode / local browser)
- Flag '--qt': Native PyQt6 GUI
- Flag '--cli': Interactive terminal mode
"""

import os
import sys

# Ensure package root is in Python module search path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


def has_display() -> bool:
    """Check if Linux graphical display server (X11 or Wayland) is available."""
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def main() -> None:
    args = sys.argv[1:]

    # Check CLI trigger flags
    cli_flags = {"--cli", "-c", "--check", "--generate", "-g", "-i", "--interactive", "--help", "-h"}
    if any(arg in cli_flags for arg in args) or not has_display():
        from src.cli.console import run_cli
        run_cli()
        return

    # Check if native Qt was specifically requested
    if "--qt" in args:
        try:
            from PyQt6.QtWidgets import QApplication
            from src.gui.main_window import MainWindow

            app = QApplication(sys.argv)
            app.setApplicationName("CodeNova Password Security Auditor")
            window = MainWindow()
            window.show()
            sys.exit(app.exec())
        except Exception as e:
            print(f"[!] PyQt6 initialization failed ({e}). Falling back to clean Web UI...\n")

    # Default Flagship: Ultra-Clean Desktop Web UI
    try:
        from src.web.server import start_server
        start_server(open_browser=True)
    except Exception as e:
        print(f"[!] Web UI server encountered an issue ({e}). Falling back to CLI mode.\n")
        from src.cli.console import run_cli
        run_cli()


if __name__ == "__main__":
    main()
