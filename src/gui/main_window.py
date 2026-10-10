"""
Streamlined, Clean PyQt6 Desktop Interface for CodeNova Password Auditor.
Minimalist, uncluttered, and responsive.
"""

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSlider,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from src.core.evaluator import EvaluationReport, PasswordEvaluator
from src.core.generator import generate_diceware_passphrase, generate_random_password
from src.gui.styles import (
    BG_CARD,
    BG_DARK,
    BG_INPUT,
    BORDER_DEFAULT,
    COLOR_CRITICAL,
    COLOR_EXCELLENT,
    COLOR_MODERATE,
    COLOR_STRONG,
    COLOR_WARNING,
    TEXT_MUTED,
    TEXT_PRIMARY,
    get_application_stylesheet,
)


class MainWindow(QMainWindow):
    """Clean, Minimalist Desktop Window."""

    def __init__(self):
        super().__init__()
        self.evaluator = PasswordEvaluator()
        self.is_password_visible = False

        self.setWindowTitle("CodeNova • Password Security Auditor")
        self.resize(880, 720)
        self.setMinimumSize(780, 600)
        self.setStyleSheet(get_application_stylesheet())

        self._setup_ui()
        self.on_password_changed("")

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(16)

        # 1. Clean Header
        header = self._create_clean_header()
        main_layout.addWidget(header)

        # 2. Modern Tab Widget
        self.tabs = QTabWidget()
        self.tab_auditor = self._create_auditor_tab()
        self.tab_generator = self._create_generator_tab()

        self.tabs.addTab(self.tab_auditor, "🔍 Password Auditor")
        self.tabs.addTab(self.tab_generator, "⚡ Secure Generator")

        main_layout.addWidget(self.tabs)

        # Shortcuts
        QShortcut(QKeySequence("Ctrl+Q"), self, self.close)
        QShortcut(QKeySequence("Esc"), self, self._clear_input)

    def _create_clean_header(self) -> QWidget:
        header = QFrame()
        header.setStyleSheet("background: transparent; border: none;")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(4, 0, 4, 0)

        vbox = QVBoxLayout()
        vbox.setSpacing(2)

        title = QLabel("CODENOVA PASSWORD AUDITOR")
        title.setStyleSheet("font-size: 18px; font-weight: 800; color: #38bdf8; letter-spacing: 0.5px;")

        sub = QLabel("Task 1 • Defensive Credential Auditing • Volatile RAM Only")
        sub.setStyleSheet(f"font-size: 12px; color: {TEXT_MUTED};")

        vbox.addWidget(title)
        vbox.addWidget(sub)
        layout.addLayout(vbox)

        layout.addStretch()

        badge = QLabel("🛡️ 100% Volatile RAM")
        badge.setStyleSheet(
            """
            background-color: rgba(16, 185, 129, 0.15);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.35);
            border-radius: 12px;
            padding: 6px 14px;
            font-size: 12px;
            font-weight: bold;
            """
        )
        layout.addWidget(badge)

        return header

    def _create_auditor_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(14)

        # Hero Input Card
        input_card = QFrame()
        input_card.setStyleSheet(
            f"background-color: {BG_CARD}; border: 1px solid {BORDER_DEFAULT}; border-radius: 14px; padding: 14px;"
        )
        in_layout = QVBoxLayout(input_card)
        in_layout.setSpacing(12)

        lbl_prompt = QLabel("Enter Credential:")
        lbl_prompt.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 12px; font-weight: bold;")
        in_layout.addWidget(lbl_prompt)

        row_input = QHBoxLayout()
        row_input.setSpacing(8)

        self.txt_password = QLineEdit()
        self.txt_password.setPlaceholderText("Type or paste password to evaluate...")
        self.txt_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.txt_password.setStyleSheet(
            f"background-color: {BG_INPUT}; font-size: 16px; padding: 12px 14px; border-radius: 8px;"
        )
        self.txt_password.textChanged.connect(self.on_password_changed)
        row_input.addWidget(self.txt_password)

        self.btn_vis = QPushButton("👁️ Show")
        self.btn_vis.setFixedWidth(80)
        self.btn_vis.clicked.connect(self._toggle_password_visibility)
        row_input.addWidget(self.btn_vis)

        self.btn_copy = QPushButton("📋 Copy")
        self.btn_copy.setFixedWidth(75)
        self.btn_copy.clicked.connect(self._copy_input)
        row_input.addWidget(self.btn_copy)

        self.btn_clear = QPushButton("✕ Clear")
        self.btn_clear.setFixedWidth(75)
        self.btn_clear.clicked.connect(self._clear_input)
        row_input.addWidget(self.btn_clear)

        in_layout.addLayout(row_input)

        # Strength Bar & Status Badge
        meter_row = QHBoxLayout()
        meter_row.setSpacing(12)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(12)
        self.progress_bar.setStyleSheet("border-radius: 6px; background-color: #1e293b;")
        meter_row.addWidget(self.progress_bar, 3)

        self.lbl_tier = QLabel("WAITING FOR INPUT")
        self.lbl_tier.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_tier.setFixedWidth(190)
        self.lbl_tier.setStyleSheet(
            f"background-color: #1e293b; color: {TEXT_MUTED}; font-weight: bold; border-radius: 6px; padding: 6px;"
        )
        meter_row.addWidget(self.lbl_tier, 1)

        in_layout.addLayout(meter_row)

        # Crack Time Highlight Banner
        self.lbl_crack_banner = QLabel("⏱️ Estimated GPU Crack Time: Instant (< 1 ms)")
        self.lbl_crack_banner.setStyleSheet(
            f"background-color: #172554; color: #93c5fd; padding: 10px 14px; border-radius: 8px; font-weight: 600;"
        )
        in_layout.addWidget(self.lbl_crack_banner)

        layout.addWidget(input_card)

        # Variety Chips Row
        self.lbl_chips = QLabel("Length: 0  |  Uppercase: ✗  |  Lowercase: ✗  |  Digits: ✗  |  Symbols: ✗")
        self.lbl_chips.setStyleSheet(
            f"background-color: {BG_CARD}; border: 1px solid {BORDER_DEFAULT}; border-radius: 10px; padding: 10px 14px; color: {TEXT_MUTED}; font-size: 13px;"
        )
        layout.addWidget(self.lbl_chips)

        # Findings & Suggestions in a Clean Split / Scroll Layout
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background: transparent; border: none;")

        scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(scroll_content)
        self.scroll_layout.setContentsMargins(0, 0, 0, 0)
        self.scroll_layout.setSpacing(10)

        # Threat Alert Card
        self.findings_card = QFrame()
        self.findings_card.setStyleSheet(
            f"background-color: {BG_CARD}; border: 1px solid {BORDER_DEFAULT}; border-radius: 12px; padding: 12px;"
        )
        self.findings_layout = QVBoxLayout(self.findings_card)
        self.findings_layout.setSpacing(6)
        self.scroll_layout.addWidget(self.findings_card)

        # Suggestions Card
        self.sugg_card = QFrame()
        self.sugg_card.setStyleSheet(
            f"background-color: {BG_CARD}; border: 1px solid {BORDER_DEFAULT}; border-radius: 12px; padding: 12px;"
        )
        self.sugg_layout = QVBoxLayout(self.sugg_card)
        self.sugg_layout.setSpacing(6)
        self.scroll_layout.addWidget(self.sugg_card)

        self.scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        return widget

    def _create_generator_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Generated Output Display Card
        out_card = QFrame()
        out_card.setStyleSheet(
            f"background-color: {BG_CARD}; border: 1px solid {BORDER_DEFAULT}; border-radius: 14px; padding: 16px;"
        )
        out_box = QVBoxLayout(out_card)
        out_box.setSpacing(12)

        lbl_out = QLabel("Generated Strong Credential:")
        lbl_out.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 12px; font-weight: bold;")
        out_box.addWidget(lbl_out)

        self.txt_gen_output = QLineEdit()
        self.txt_gen_output.setReadOnly(True)
        self.txt_gen_output.setStyleSheet(
            f"font-size: 18px; font-weight: bold; color: {COLOR_EXCELLENT}; padding: 12px; background-color: {BG_INPUT}; border-radius: 8px;"
        )
        out_box.addWidget(self.txt_gen_output)

        btn_row = QHBoxLayout()
        self.btn_gen_now = QPushButton("⚡ Generate")
        self.btn_gen_now.setObjectName("primaryButton")
        self.btn_gen_now.clicked.connect(self._generate_credential)
        btn_row.addWidget(self.btn_gen_now)

        self.btn_copy_gen = QPushButton("📋 Copy to Clipboard")
        self.btn_copy_gen.clicked.connect(self._copy_generated)
        btn_row.addWidget(self.btn_copy_gen)

        self.btn_audit_gen = QPushButton("🔍 Audit in Checker")
        self.btn_audit_gen.clicked.connect(self._use_in_auditor)
        btn_row.addWidget(self.btn_audit_gen)

        out_box.addLayout(btn_row)
        layout.addWidget(out_card)

        # Parameters Card
        param_card = QFrame()
        param_card.setStyleSheet(
            f"background-color: {BG_CARD}; border: 1px solid {BORDER_DEFAULT}; border-radius: 14px; padding: 16px;"
        )
        p_box = QVBoxLayout(param_card)
        p_box.setSpacing(12)

        # Mode
        m_row = QHBoxLayout()
        m_lbl = QLabel("Mode:")
        m_lbl.setFixedWidth(80)
        self.combo_mode = QComboBox()
        self.combo_mode.addItems(["Random Characters", "Diceware Passphrase"])
        self.combo_mode.currentIndexChanged.connect(self._on_gen_mode_changed)
        m_row.addWidget(m_lbl)
        m_row.addWidget(self.combo_mode)
        p_box.addLayout(m_row)

        # Length
        len_row = QHBoxLayout()
        self.lbl_len = QLabel("Length:")
        self.lbl_len.setFixedWidth(80)
        self.slider_len = QSlider(Qt.Orientation.Horizontal)
        self.slider_len.setRange(8, 40)
        self.slider_len.setValue(18)
        self.spin_len = QSpinBox()
        self.spin_len.setRange(8, 40)
        self.spin_len.setValue(18)
        self.slider_len.valueChanged.connect(self.spin_len.setValue)
        self.spin_len.valueChanged.connect(self.slider_len.setValue)

        len_row.addWidget(self.lbl_len)
        len_row.addWidget(self.slider_len)
        len_row.addWidget(self.spin_len)
        p_box.addLayout(len_row)

        # Checkboxes
        self.chk_upper = QCheckBox("Uppercase (A-Z)")
        self.chk_upper.setChecked(True)
        self.chk_lower = QCheckBox("Lowercase (a-z)")
        self.chk_lower.setChecked(True)
        self.chk_digits = QCheckBox("Numbers (0-9)")
        self.chk_digits.setChecked(True)
        self.chk_symbols = QCheckBox("Symbols (!@#$)")
        self.chk_symbols.setChecked(True)

        p_box.addWidget(self.chk_upper)
        p_box.addWidget(self.chk_lower)
        p_box.addWidget(self.chk_digits)
        p_box.addWidget(self.chk_symbols)

        layout.addWidget(param_card)
        layout.addStretch()

        self._generate_credential()
        return widget

    def on_password_changed(self, text: str) -> None:
        rep = self.evaluator.evaluate(text)

        # Update progress and badge
        self.progress_bar.setValue(rep.score)
        self.progress_bar.setStyleSheet(
            f"QProgressBar::chunk {{ background-color: {rep.tier_color}; border-radius: 6px; }}"
        )

        if rep.password_length == 0:
            self.lbl_tier.setText("WAITING FOR INPUT")
            self.lbl_tier.setStyleSheet(
                f"background-color: #1e293b; color: {TEXT_MUTED}; font-weight: bold; border-radius: 6px; padding: 6px;"
            )
            self.lbl_crack_banner.setText("⏱️ Estimated GPU Crack Time: Instant (< 1 ms)")
        else:
            self.lbl_tier.setText(f"{rep.tier.upper()} ({rep.score}/100)")
            self.lbl_tier.setStyleSheet(
                f"background-color: #1e293b; color: {rep.tier_color}; font-weight: bold; border: 1px solid {rep.tier_color}; border-radius: 6px; padding: 6px;"
            )
            self.lbl_crack_banner.setText(
                f"⏱️ Estimated GPU Crack Time: {rep.crack_times.offline_fast_hash.human_readable}  (Shannon Entropy: {rep.entropy.total_shannon_entropy:.1f} bits)"
            )

        # Update chips
        v = rep.entropy.variety
        self.lbl_chips.setText(
            f"Length: {rep.password_length} {'✓' if rep.password_length >= 14 else '✗'}   |   "
            f"Upper: {'✓' if v.has_upper else '✗'}   |   "
            f"Lower: {'✓' if v.has_lower else '✗'}   |   "
            f"Digits: {'✓' if v.has_digits else '✗'}   |   "
            f"Symbols: {'✓' if v.has_symbols else '✗'}"
        )

        # Update findings
        self._clear_layout(self.findings_layout)
        f_title = QLabel("Detected Issues & Threat Patterns:")
        f_title.setStyleSheet("font-weight: bold; font-size: 13px; color: #f8fafc;")
        self.findings_layout.addWidget(f_title)

        if rep.password_length == 0:
            lbl = QLabel("Enter a password above to view analysis.")
            lbl.setStyleSheet(f"color: {TEXT_MUTED}; font-style: italic;")
            self.findings_layout.addWidget(lbl)
        else:
            has_issues = False
            for df in rep.dictionary_findings:
                has_issues = True
                lbl = QLabel(f"🚨 {df.description}")
                lbl.setStyleSheet(f"color: {COLOR_CRITICAL}; font-weight: bold; padding: 2px 0;")
                self.findings_layout.addWidget(lbl)

            for pf in rep.pattern_findings:
                has_issues = True
                col = COLOR_CRITICAL if pf.severity == "high" else COLOR_WARNING
                lbl = QLabel(f"⚡ {pf.description} [Snippet: '{pf.match_snippet}']")
                lbl.setStyleSheet(f"color: {col}; font-weight: bold; padding: 2px 0;")
                self.findings_layout.addWidget(lbl)

            if not has_issues:
                lbl = QLabel("✓ Zero dictionary words or predictable patterns found.")
                lbl.setStyleSheet(f"color: {COLOR_STRONG}; font-weight: bold;")
                self.findings_layout.addWidget(lbl)

        # Update suggestions
        self._clear_layout(self.sugg_layout)
        s_title = QLabel("Actionable Strengthening Advice:")
        s_title.setStyleSheet("font-weight: bold; font-size: 13px; color: #f8fafc;")
        self.sugg_layout.addWidget(s_title)

        if not rep.suggestions:
            lbl = QLabel("✓ Credential meets all security standards.")
            lbl.setStyleSheet(f"color: {COLOR_STRONG}; font-weight: bold;")
            self.sugg_layout.addWidget(lbl)
        else:
            for s in rep.suggestions:
                lbl = QLabel(f"• {s}")
                lbl.setWordWrap(True)
                lbl.setStyleSheet(f"color: {TEXT_PRIMARY}; padding: 2px 0;")
                self.sugg_layout.addWidget(lbl)

    def _clear_layout(self, layout) -> None:
        while layout.count() > 0:
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _toggle_password_visibility(self) -> None:
        self.is_password_visible = not self.is_password_visible
        if self.is_password_visible:
            self.txt_password.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_vis.setText("🙈 Hide")
        else:
            self.txt_password.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_vis.setText("👁️ Show")

    def _clear_input(self) -> None:
        self.txt_password.clear()
        self.txt_password.setFocus()

    def _copy_input(self) -> None:
        text = self.txt_password.text()
        if text:
            QApplication.clipboard().setText(text)
            self.btn_copy.setText("✓ Copied")
            QTimer.singleShot(1500, lambda: self.btn_copy.setText("📋 Copy"))

    def _on_gen_mode_changed(self, idx: int) -> None:
        if idx == 1:
            self.lbl_len.setText("Words:")
            self.slider_len.setRange(3, 8)
            self.slider_len.setValue(5)
            self.spin_len.setRange(3, 8)
            self.spin_len.setValue(5)
        else:
            self.lbl_len.setText("Length:")
            self.slider_len.setRange(8, 40)
            self.slider_len.setValue(18)
            self.spin_len.setRange(8, 40)
            self.spin_len.setValue(18)
        self._generate_credential()

    def _generate_credential(self) -> None:
        if self.combo_mode.currentIndex() == 1:
            pwd = generate_diceware_passphrase(num_words=self.spin_len.value())
        else:
            pwd = generate_random_password(
                length=self.spin_len.value(),
                include_upper=self.chk_upper.isChecked(),
                include_lower=self.chk_lower.isChecked(),
                include_digits=self.chk_digits.isChecked(),
                include_symbols=self.chk_symbols.isChecked(),
            )
        self.txt_gen_output.setText(pwd)

    def _copy_generated(self) -> None:
        pwd = self.txt_gen_output.text()
        if pwd:
            QApplication.clipboard().setText(pwd)
            self.btn_copy_gen.setText("✓ Copied!")
            QTimer.singleShot(1500, lambda: self.btn_copy_gen.setText("📋 Copy to Clipboard"))

    def _use_in_auditor(self) -> None:
        pwd = self.txt_gen_output.text()
        if pwd:
            self.txt_password.setText(pwd)
            self.tabs.setCurrentIndex(0)
