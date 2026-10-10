"""
Lightweight In-Memory Local Web Server for CodeNova Password Strength Checker.
Runs purely on 127.0.0.1, performs evaluations in volatile memory, and serves
the ultra-clean modern desktop UI.
"""

import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser

from src.core.evaluator import PasswordEvaluator
from src.core.generator import generate_diceware_passphrase, generate_random_password

WEB_DIR = Path(__file__).resolve().parent


class AuditRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler serving static UI files and volatile API endpoints."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def log_message(self, format, *args):
        # Suppress routine request logging to keep console clean
        pass

    def do_POST(self):
        """Handle JSON API evaluation and generation requests in volatile RAM."""
        parsed_url = urllib.parse.urlparse(self.path)

        if parsed_url.path == "/api/evaluate":
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length)
            try:
                data = json.loads(raw_body.decode("utf-8"))
                password = data.get("password", "")
            except Exception:
                password = ""

            # Evaluate purely in volatile memory
            evaluator = PasswordEvaluator.get_instance() if hasattr(PasswordEvaluator, "get_instance") else PasswordEvaluator()
            rep = evaluator.evaluate(password)

            response_data = {
                "password_length": rep.password_length,
                "score": rep.score,
                "tier": rep.tier,
                "tier_color": rep.tier_color,
                "shannon_entropy": {
                    "total_bits": rep.entropy.total_shannon_entropy,
                    "bits_per_char": rep.entropy.shannon_bits_per_char,
                },
                "keyspace_entropy": {
                    "entropy_bits": rep.entropy.keyspace_entropy_bits,
                    "pool_size": rep.entropy.keyspace_pool_size,
                    "unique_chars": rep.entropy.unique_chars,
                },
                "crack_times": {
                    "online": rep.crack_times.online_attack.human_readable,
                    "fast_gpu": rep.crack_times.offline_fast_hash.human_readable,
                    "slow_argon2": rep.crack_times.offline_slow_hash.human_readable,
                },
                "variety": {
                    "has_lower": rep.entropy.variety.has_lower,
                    "has_upper": rep.entropy.variety.has_upper,
                    "has_digits": rep.entropy.variety.has_digits,
                    "has_symbols": rep.entropy.variety.has_symbols,
                    "lower_count": rep.entropy.variety.lower_count,
                    "upper_count": rep.entropy.variety.upper_count,
                    "digit_count": rep.entropy.variety.digit_count,
                    "symbol_count": rep.entropy.variety.symbol_count,
                },
                "pattern_findings": [
                    {
                        "category": pf.category,
                        "description": pf.description,
                        "match_snippet": pf.match_snippet,
                        "severity": pf.severity,
                        "penalty": pf.penalty_score,
                    }
                    for pf in rep.pattern_findings
                ],
                "dictionary_findings": [
                    {
                        "matched_word": df.matched_word,
                        "match_type": df.match_type,
                        "severity": df.severity,
                        "description": df.description,
                        "penalty": df.penalty_score,
                    }
                    for df in rep.dictionary_findings
                ],
                "suggestions": rep.suggestions,
                "passed_checks": rep.passed_checks,
                "failed_checks": rep.failed_checks,
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode("utf-8"))
            return

        elif parsed_url.path == "/api/generate":
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length)
            try:
                data = json.loads(raw_body.decode("utf-8"))
            except Exception:
                data = {}

            mode = data.get("mode", "random")
            if mode == "passphrase":
                num_words = int(data.get("words", 5))
                sep = data.get("separator", "-")
                cap = bool(data.get("capitalize", True))
                num = bool(data.get("append_number", True))
                pwd = generate_diceware_passphrase(
                    num_words=num_words,
                    separator=sep,
                    capitalize=cap,
                    append_number=num,
                )
            else:
                length = int(data.get("length", 18))
                upper = bool(data.get("upper", True))
                lower = bool(data.get("lower", True))
                digits = bool(data.get("digits", True))
                symbols = bool(data.get("symbols", True))
                no_ambig = bool(data.get("no_ambiguous", False))
                pwd = generate_random_password(
                    length=length,
                    include_upper=upper,
                    include_lower=lower,
                    include_digits=digits,
                    include_symbols=symbols,
                    exclude_ambiguous=no_ambig,
                )

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"password": pwd}).encode("utf-8"))
            return

        self.send_error(404, "Endpoint Not Found")


def find_free_port(start_port: int = 5055) -> int:
    """Find an available TCP port on localhost."""
    for port in range(start_port, start_port + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start_port


def open_desktop_window(url: str) -> None:
    """Launch URL in standalone desktop window via Chromium app mode or browser on Linux."""
    candidates = ["chromium", "google-chrome", "chromium-browser", "brave-browser"]

    # Try Chromium-based standalone app window mode on Linux
    for browser_bin in candidates:
        try:
            cmd = [browser_bin, f"--app={url}", "--window-size=1080,820", "--app-id=codenova-password-auditor"]
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except (FileNotFoundError, OSError):
            continue

    # Fallback to system default Linux browser via xdg-open / webbrowser
    try:
        webbrowser.open(url)
    except Exception:
        pass


def start_server(port: int = 0, open_browser: bool = True) -> None:
    """Start the local web UI server."""
    if port == 0:
        port = find_free_port()

    server_address = ("127.0.0.1", port)

    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    with ReusableTCPServer(server_address, AuditRequestHandler) as httpd:
        url = f"http://127.0.0.1:{port}"
        print(f"\n[✓] CodeNova Password Security Suite running at: {url}")
        print("    (Running 100% offline in volatile RAM • Press Ctrl+C to stop)\n")

        if open_browser:
            threading.Thread(target=lambda: (time.sleep(0.4), open_desktop_window(url)), daemon=True).start()

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Stopping server. Volatile memory cleared.")


if __name__ == "__main__":
    start_server()
