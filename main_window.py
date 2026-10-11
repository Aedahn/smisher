"""Main application window."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStatusBar,
    QTextBrowser,
    QTextEdit,
    QToolBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from analyzer_runner import AnalyzerRunner
from csv_io import export_results, import_csv
from database import FOLDER_INBOX, FOLDER_PHISHING, Database, Email
from email_renderer import open_external_url, render_plain_text
from themes import DARK_THEME, LIGHT_THEME, build_stylesheet
from widgets import (
    AgentCard,
    Card,
    ConfidenceBar,
    EmailListItem,
    StatCard,
    VerdictBadge,
)


# ----------------------------------------------------------------------
# Dialog for manual email insertion
# ----------------------------------------------------------------------
class EmailInputDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Insert Manual Email")
        self.setMinimumSize(600, 500)
        layout = QVBoxLayout(self)

        # Correct class (label) first
        label_label = QLabel("True Label (optional):")
        self.label_combo = QComboBox()
        self.label_combo.addItems(["Unknown", "Legitimate", "Phishing"])
        layout.addWidget(label_label)
        layout.addWidget(self.label_combo)

        # Metadata
        meta_label = QLabel("Metadata (email headers):")
        self.meta_edit = QTextEdit()
        self.meta_edit.setPlaceholderText(
            "e.g., From: sender@example.com\nSubject: Hello\nDate: ..."
        )
        self.meta_edit.setMaximumHeight(150)
        layout.addWidget(meta_label)
        layout.addWidget(self.meta_edit)

        # Body (last)
        body_label = QLabel("Email Body:")
        self.body_edit = QTextEdit()
        self.body_edit.setPlaceholderText("Paste the email body text here...")
        layout.addWidget(body_label)
        layout.addWidget(self.body_edit)

        # Buttons
        btn_box = QHBoxLayout()
        ok_btn = QPushButton("Insert")
        ok_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_box.addWidget(ok_btn)
        btn_box.addWidget(cancel_btn)
        layout.addLayout(btn_box)

    def get_email_data(self):
        body = self.body_edit.toPlainText().strip()
        metadata = self.meta_edit.toPlainText().strip()
        label_text = self.label_combo.currentText()
        if label_text == "Phishing":
            label = 1
        elif label_text == "Legitimate":
            label = 0
        else:
            label = None
        return body, metadata, label


# ----------------------------------------------------------------------
# Main Window
# ----------------------------------------------------------------------
@dataclass
class UndoAction:
    email_id: int
    previous_folder: str


class MainWindow(QMainWindow):
    def __init__(self, db: Database) -> None:
        super().__init__()
        self.db = db
        self.current_folder = FOLDER_INBOX
        self.current_email: Email | None = None
        self.theme = LIGHT_THEME
        self._undo_stack: list[UndoAction] = []
        self._analyzer = AnalyzerRunner(self)
        self._analyzer.single_finished.connect(self._on_analysis_done)
        self._analyzer.single_error.connect(self._on_analysis_error)
        self._analyzer.batch_progress.connect(self._on_batch_progress)
        self._analyzer.batch_finished.connect(self._on_batch_finished)
        self._analyzer.batch_cancelled.connect(self._on_batch_cancelled)
        self._analyzer.status_message.connect(self._on_analyzer_status)
        self._analyzer.busy_changed.connect(self._on_analyzer_busy)
        self._selected_model = "gemma2_9b"

        self.setWindowTitle("Multi LLMs — Phishing Detection Demo")
        self.setMinimumSize(1280, 800)
        self.resize(1440, 900)

        self._build_ui()
        self._build_menu()
        self._build_toolbar()
        self._apply_theme(self._load_theme_preference())
        self._toggle_agent_details(False)
        self._switch_folder(FOLDER_INBOX)
        self._refresh_statistics()
        self._clear_detail_panels()
        self._update_analyze_all_button()

    def _load_theme_preference(self) -> dict:
        saved = self.db.get_setting("theme", "light")
        return DARK_THEME if saved == "dark" else LIGHT_THEME

    def _save_theme_preference(self) -> None:
        self.db.set_setting("theme", self.theme["name"])

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_top_bar())

        splitter = QSplitter(Qt.Orientation.Horizontal)

        list_panel = QFrame()
        list_panel.setObjectName("listPanel")
        list_layout = QVBoxLayout(list_panel)
        list_layout.setContentsMargins(12, 8, 6, 12)
        list_header = QLabel("Emails")
        list_header.setObjectName("panelHeader")
        self.email_list = QListWidget()
        self.email_list.setSpacing(6)
        self.email_list.setAlternatingRowColors(True)
        self.email_list.setUniformItemSizes(False)
        self.email_list.setMinimumWidth(420)
        self.email_list.currentRowChanged.connect(self._on_email_selected)
        list_layout.addWidget(list_header)
        list_layout.addWidget(self.email_list)
        splitter.addWidget(list_panel)

        viewer_panel = QFrame()
        viewer_panel.setObjectName("viewerPanel")
        viewer_layout = QVBoxLayout(viewer_panel)
        viewer_layout.setContentsMargins(6, 8, 6, 12)
        viewer_header = QHBoxLayout()
        self.viewer_title = QLabel("Select an email")
        self.viewer_title.setObjectName("panelHeader")
        viewer_header.addWidget(self.viewer_title)
        viewer_header.addStretch()
        self.trust_btn = QPushButton("Trust Email")
        self.trust_btn.setObjectName("successBtn")
        self.trust_btn.clicked.connect(self._trust_email)
        self.move_btn = QPushButton("Move to Phishing")
        self.move_btn.setObjectName("dangerBtn")
        self.move_btn.clicked.connect(self._move_email)
        self.restore_btn = QPushButton("Restore to Inbox")
        self.restore_btn.setObjectName("primaryBtn")
        self.restore_btn.clicked.connect(self._restore_email)
        self.remove_btn = QPushButton("Remove Email")
        self.remove_btn.setObjectName("dangerBtn")
        self.remove_btn.clicked.connect(self._remove_email)
        self.undo_btn = QPushButton("Undo")
        self.undo_btn.setObjectName("secondaryBtn")
        self.undo_btn.clicked.connect(self._undo_move)
        viewer_header.addWidget(self.undo_btn)
        viewer_header.addWidget(self.trust_btn)
        viewer_header.addWidget(self.move_btn)
        viewer_header.addWidget(self.restore_btn)
        viewer_header.addWidget(self.remove_btn)
        viewer_layout.addLayout(viewer_header)

        meta_label = QLabel("Metadata")
        meta_label.setObjectName("sectionSubHeader")
        self.metadata_view = QTextBrowser()
        self.metadata_view.setOpenExternalLinks(False)
        self.metadata_view.setMaximumHeight(160)
        self.metadata_view.anchorClicked.connect(self._on_link_clicked)

        body_label = QLabel("Body")
        body_label.setObjectName("sectionSubHeader")
        self.body_view = QTextBrowser()
        self.body_view.setOpenExternalLinks(False)
        self.body_view.anchorClicked.connect(self._on_link_clicked)

        viewer_layout.addWidget(meta_label)
        viewer_layout.addWidget(self.metadata_view)
        viewer_layout.addWidget(body_label)
        viewer_layout.addWidget(self.body_view, 1)
        splitter.addWidget(viewer_panel)

        analysis_scroll = QScrollArea()
        analysis_scroll.setWidgetResizable(True)
        analysis_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        analysis_widget = QWidget()
        analysis_layout = QVBoxLayout(analysis_widget)
        analysis_layout.setContentsMargins(6, 8, 12, 12)

        analysis_header = QLabel("Analysis")
        analysis_header.setObjectName("panelHeader")
        analysis_layout.addWidget(analysis_header)

        action_row = QHBoxLayout()
        self.analyze_btn = QPushButton("Analyze Email")
        self.analyze_btn.setObjectName("primaryBtn")
        self.analyze_btn.clicked.connect(self._analyze_current)
        self.cancel_batch_btn = QPushButton("Cancel")
        self.cancel_batch_btn.setVisible(False)
        self.cancel_batch_btn.clicked.connect(self._cancel_analysis)
        self.details_toggle = QToolButton()
        self.details_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.details_toggle.setText(" Agent details")
        self.details_toggle.setArrowType(Qt.ArrowType.RightArrow)
        self.details_toggle.setCheckable(True)
        self.details_toggle.setChecked(False)
        self.details_toggle.setVisible(False)
        self.details_toggle.toggled.connect(self._toggle_agent_details)
        action_row.addWidget(self.analyze_btn)
        action_row.addWidget(self.cancel_batch_btn)
        action_row.addStretch()
        analysis_layout.addLayout(action_row)

        self.single_progress = QProgressBar()
        self.single_progress.setVisible(False)
        self.single_progress.setRange(0, 0)
        self.single_progress.setTextVisible(True)
        self.single_progress.setFormat("Analyzing email…")
        self.single_progress.setMaximumHeight(10)
        self.single_progress.setObjectName("analysisProgress")
        analysis_layout.addWidget(self.single_progress)

        self.batch_progress = QProgressBar()
        self.batch_progress.setVisible(False)
        self.batch_label = QLabel("")
        self.batch_label.setVisible(False)
        analysis_layout.addWidget(self.batch_label)
        analysis_layout.addWidget(self.batch_progress)

        # --- Predicted class section ---
        predicted_title = QLabel("Predicted class")
        predicted_title.setObjectName("sectionSubHeader")
        analysis_layout.addWidget(predicted_title)
        self.verdict_badge = VerdictBadge()
        analysis_layout.addWidget(self.verdict_badge)

        # --- Correct class section (always visible, shows UNKNOWN if no label) ---
        self.correct_section = QWidget()
        correct_layout = QVBoxLayout(self.correct_section)
        correct_layout.setContentsMargins(0, 8, 0, 0)
        correct_layout.setSpacing(6)

        correct_title = QLabel("Correct class")
        correct_title.setObjectName("sectionSubHeader")
        self.true_badge = QLabel()
        self.true_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.true_badge.setMinimumHeight(56)
        self.true_badge.setStyleSheet(
            "font-size: 22px; font-weight: 700; border-radius: 8px; padding: 12px;"
        )

        correct_layout.addWidget(correct_title)
        correct_layout.addWidget(self.true_badge)

        analysis_layout.addWidget(self.correct_section)

        self.confidence_bar = ConfidenceBar()
        analysis_layout.addWidget(self.confidence_bar)

        self.time_label = QLabel("")
        self.time_label.setObjectName("detailLabel")
        analysis_layout.addWidget(self.time_label)

        self.model_used_label = QLabel("")
        self.model_used_label.setObjectName("detailLabel")
        analysis_layout.addWidget(self.model_used_label)

        self.explanation_card = Card()
        explain_title = QLabel("Explanation")
        explain_title.setObjectName("sectionSubHeader")
        self.explanation_view = QLabel("—")
        self.explanation_view.setWordWrap(True)
        self.explanation_card.add_widget(explain_title)
        self.explanation_card.add_widget(self.explanation_view)
        analysis_layout.addWidget(self.explanation_card)
        analysis_layout.addWidget(self.details_toggle, 0, Qt.AlignmentFlag.AlignRight)

        self.agents_group = QGroupBox("Agent Analysis")
        self.agents_group.setCheckable(False)
        self.agents_group.setChecked(True)
        agents_layout = QVBoxLayout(self.agents_group)
        self.text_agent = AgentCard("Text Agent")
        self.url_agent = AgentCard("URL Agent")
        self.meta_agent = AgentCard("Metadata Agent")
        agents_layout.addWidget(self.text_agent)
        agents_layout.addWidget(self.url_agent)
        agents_layout.addWidget(self.meta_agent)
        analysis_layout.addWidget(self.agents_group)

        analysis_layout.addStretch()
        analysis_scroll.setWidget(analysis_widget)
        splitter.addWidget(analysis_scroll)

        splitter.setSizes([380, 520, 340])
        root.addWidget(splitter, 1)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Ready")

    def _build_top_bar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("topBar")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(12)

        title = QLabel("Multi LLMs")
        title.setObjectName("appTitle")
        title.setFont(QFont("", 18, QFont.Weight.Bold))
        layout.addWidget(title)

        layout.addWidget(self._vline())

        self.inbox_btn = QPushButton("Inbox")
        self.inbox_btn.setObjectName("topFolderBtn")
        self.inbox_btn.clicked.connect(lambda: self._switch_folder(FOLDER_INBOX))
        self.phishing_btn = QPushButton("Phishing Folder")
        self.phishing_btn.setObjectName("topFolderBtn")
        self.phishing_btn.clicked.connect(lambda: self._switch_folder(FOLDER_PHISHING))
        self.analyze_all_top_btn = QPushButton("Analyze All")
        self.analyze_all_top_btn.setObjectName("topFolderBtn")
        self.analyze_all_top_btn.clicked.connect(self._analyze_all)
        self.remove_all_top_btn = QPushButton("Remove All")
        self.remove_all_top_btn.setObjectName("topFolderBtn")
        self.remove_all_top_btn.clicked.connect(self._remove_all_emails)

        layout.addWidget(self.inbox_btn)
        layout.addWidget(self.phishing_btn)
        layout.addWidget(self.analyze_all_top_btn)
        layout.addWidget(self.remove_all_top_btn)

        layout.addWidget(self._vline())

        self.stat_total = StatCard("Total", compact=True)
        self.stat_analyzed = StatCard("Analyzed", compact=True)
        self.stat_legit = StatCard("Legitimate", compact=True)
        self.stat_phishing = StatCard("Phishing", compact=True)
        self.stat_correct = StatCard("Correct", compact=True)
        self.stat_incorrect = StatCard("Incorrect", compact=True)
        self.stat_avg_time = StatCard("Avg Time", compact=True)

        for card in (
            self.stat_total,
            self.stat_analyzed,
            self.stat_legit,
            self.stat_phishing,
            self.stat_correct,
            self.stat_incorrect,
            self.stat_avg_time,
        ):
            layout.addWidget(card)

        layout.addStretch()
        return bar

    def _vline(self) -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.Shape.VLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        line.setFixedWidth(1)
        return line

    def _build_menu(self) -> None:
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")
        export_action = QAction("Export Results…", self)
        export_action.triggered.connect(self._export_results)
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(export_action)
        file_menu.addSeparator()
        file_menu.addAction(quit_action)

        view_menu = menubar.addMenu("View")
        self.theme_action = QAction("Dark Mode", self)
        self.theme_action.setCheckable(True)
        self.theme_action.triggered.connect(self._toggle_theme)
        view_menu.addAction(self.theme_action)

        help_menu = menubar.addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _build_toolbar(self) -> None:
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        # Insert Email button first
        insert_btn = QPushButton("Insert Email")
        insert_btn.clicked.connect(self._insert_manual_email)

        # Import CSV button
        import_btn = QPushButton("Import CSV")
        import_btn.clicked.connect(self._import_csv)

        export_btn = QPushButton("Export Results")
        export_btn.clicked.connect(self._export_results)

        self.dark_mode_btn = QPushButton("Dark Mode")
        self.dark_mode_btn.setCheckable(True)
        self.dark_mode_btn.clicked.connect(self._toggle_theme)

        toolbar.addWidget(insert_btn)
        toolbar.addWidget(import_btn)
        toolbar.addSeparator()
        toolbar.addWidget(export_btn)
        toolbar.addSeparator()
        toolbar.addWidget(self.dark_mode_btn)

    def _apply_theme(self, theme: dict) -> None:
        self.theme = theme
        self.setStyleSheet(build_stylesheet(theme))
        self.verdict_badge.set_dark_mode(theme["name"] == "dark")
        is_dark = theme["name"] == "dark"
        self.theme_action.setText("Light Mode" if is_dark else "Dark Mode")
        self.dark_mode_btn.setText("Light Mode" if is_dark else "Dark Mode")
        self.theme_action.blockSignals(True)
        self.theme_action.setChecked(is_dark)
        self.theme_action.blockSignals(False)
        self.dark_mode_btn.blockSignals(True)
        self.dark_mode_btn.setChecked(is_dark)
        self.dark_mode_btn.blockSignals(False)
        self._save_theme_preference()
        if self.current_email:
            self._display_analysis(self.current_email)

    def _toggle_theme(self) -> None:
        new_theme = DARK_THEME if self.theme["name"] == "light" else LIGHT_THEME
        self._apply_theme(new_theme)
        if self.current_email:
            self._display_email(self.current_email)

    def _switch_folder(self, folder: str) -> None:
        self.current_folder = folder
        self.inbox_btn.setProperty("active", folder == FOLDER_INBOX)
        self.phishing_btn.setProperty("active", folder == FOLDER_PHISHING)
        for btn in (self.inbox_btn, self.phishing_btn):
            btn.style().unpolish(btn)
            btn.style().polish(btn)

        self.move_btn.setVisible(folder == FOLDER_INBOX)
        self.restore_btn.setVisible(folder == FOLDER_PHISHING)
        self.undo_btn.setVisible(folder == FOLDER_PHISHING)
        self._refresh_email_list()

    def _refresh_email_list(self) -> None:
        selected_id = None
        row = self.email_list.currentRow()
        if row >= 0:
            item = self.email_list.item(row)
            if item:
                selected_id = item.data(Qt.ItemDataRole.UserRole)

        self.email_list.blockSignals(True)
        self.email_list.clear()
        emails = self.db.get_emails(self.current_folder)
        restore_row = -1
        for i, email in enumerate(emails):
            item = QListWidgetItem(self.email_list)
            item.setData(Qt.ItemDataRole.UserRole, email.id)
            widget = EmailListItem(email)
            item.setSizeHint(widget.sizeHint())
            self.email_list.addItem(item)
            self.email_list.setItemWidget(item, widget)
            if email.id == selected_id:
                restore_row = i
        self.email_list.blockSignals(False)

        if restore_row >= 0:
            self.email_list.setCurrentRow(restore_row)
        elif emails:
            self.email_list.setCurrentRow(0)

        folder_name = "Inbox" if self.current_folder == FOLDER_INBOX else "Phishing Folder"
        self.status.showMessage(f"{folder_name}: {len(emails)} email(s)")
        self._update_list_progress()
        self._update_analyze_all_button()

    def _refresh_statistics(self) -> None:
        stats = self.db.get_statistics()
        self.stat_total.set_value(str(stats["total"]))
        self.stat_analyzed.set_value(str(stats["analyzed"]))
        self.stat_legit.set_value(str(stats["legitimate_predictions"]))
        self.stat_phishing.set_value(str(stats["phishing_predictions"]))
        self.stat_correct.set_value(str(stats["correct"]))
        self.stat_incorrect.set_value(str(stats["incorrect"]))
        avg = stats["avg_analysis_time"]
        self.stat_avg_time.set_value(f"{avg:.2f}" if avg else "—")

    def _update_analyze_all_button(self) -> None:
        if self._analyzer.is_batch_active:
            self.analyze_all_top_btn.setText("Cancel")
            self.analyze_all_top_btn.setEnabled(True)
            return

        unanalyzed = self.db.get_unanalyzed_emails()
        if not unanalyzed:
            self.analyze_all_top_btn.setText("Analyze All")
            self.analyze_all_top_btn.setEnabled(False)
        else:
            self.analyze_all_top_btn.setText("Analyze All")
            self.analyze_all_top_btn.setEnabled(not self._analyzer.is_busy())

    def _update_list_progress(self) -> None:
        for row in range(self.email_list.count()):
            item = self.email_list.item(row)
            if not item:
                continue
            widget = self.email_list.itemWidget(item)
            if not isinstance(widget, EmailListItem):
                continue
            email_id = item.data(Qt.ItemDataRole.UserRole)
            state = self._analyzer.get_email_analysis_state(email_id)
            widget.set_analysis_state(state)
            item.setSizeHint(widget.sizeHint())

    def _on_email_selected(self, row: int) -> None:
        if row < 0:
            self.current_email = None
            self._clear_detail_panels()
            return
        item = self.email_list.item(row)
        if not item:
            return
        email_id = item.data(Qt.ItemDataRole.UserRole)
        email = self.db.get_email(email_id)
        if email:
            self.current_email = email
            self._display_email(email)
            self._display_analysis(email)

    def _display_email(self, email: Email) -> None:
        self.viewer_title.setText(email.subject)
        links = email.trusted
        self.metadata_view.setHtml(render_plain_text(email.metadata, links))
        self.body_view.setHtml(render_plain_text(email.body, links))
        self.trust_btn.setEnabled(not email.trusted)
        self.trust_btn.setText("Trusted" if email.trusted else "Trust Email")
        self.remove_btn.setVisible(True)

    def _selected_model_name(self) -> str:
        return "gemma2_9b"

    def _has_result_for_selected_model(self, email: Email) -> bool:
        if not email.is_analyzed:
            return False
        model_name = (email.model or "").strip().lower()
        return model_name == self._selected_model_name()

    def _display_analysis(self, email: Email) -> None:
        selected_model = self._selected_model_name()
        has_selected_result = self._has_result_for_selected_model(email)
        is_currently_running = self._analyzer.current_email_id == email.id
        in_progress = self._analyzer.is_email_in_progress(email.id)

        self.single_progress.setVisible(
            is_currently_running or (in_progress and not has_selected_result)
        )
        if is_currently_running:
            self.single_progress.setFormat(f"Analyzing email #{email.email_index}…")
        elif in_progress and not has_selected_result:
            self.single_progress.setFormat(f"Queued #{email.email_index}…")

        if has_selected_result:
            self.verdict_badge.set_verdict(email.final_verdict)
            self.confidence_bar.set_confidence(
                (1.0 - email.phishing_score)
                if email.final_verdict
                and email.final_verdict.lower() == "legitimate"
                and email.phishing_score is not None
                else email.phishing_score,
                "Confidence",
            )

            # --- Correct class badge (true label) ---
            self.correct_section.setVisible(True)
            is_dark = self.theme["name"] == "dark"

            if email.label == 1:
                true_text = "PHISHING"
                if is_dark:
                    bg, fg, border = "#7f1d1d", "#fca5a5", "#991b1b"
                else:
                    bg, fg, border = "#fee2e2", "#dc2626", "#fecaca"
            elif email.label == 0:
                true_text = "LEGITIMATE"
                if is_dark:
                    bg, fg, border = "#14532d", "#86efac", "#166534"
                else:
                    bg, fg, border = "#dcfce7", "#16a34a", "#bbf7d0"
            else:
                # Unknown / missing label
                true_text = "UNKNOWN"
                if is_dark:
                    bg, fg, border = "#374151", "#9ca3af", "#4b5563"
                else:
                    bg, fg, border = "#f1f5f9", "#64748b", "#e2e8f0"

            self.true_badge.setText(true_text)
            self.true_badge.setStyleSheet(
                f"background: {bg}; color: {fg}; border: 1px solid {border};"
                "font-size: 22px; font-weight: 700; border-radius: 8px; padding: 12px;"
            )
            # --- end correct class ---

            self.time_label.setText(
                f"Analyzed in {email.analysis_time_seconds:.2f} seconds"
                if email.analysis_time_seconds is not None
                else ""
            )
            self.model_used_label.setText(f"Model: {email.model}" if email.model else "")
            self.explanation_view.setText(email.explanation or "—")
            self.explanation_card.setVisible(True)
            self.details_toggle.setVisible(True)
            self.text_agent.set_data(
                email.text_verdict, email.text_confidence, email.text_reason
            )
            self.url_agent.set_data(
                email.url_verdict, email.url_confidence, email.url_reason
            )
            self.meta_agent.set_data(
                email.meta_verdict, email.meta_confidence, email.meta_reason
            )
            self.analyze_btn.setText("Analyze Email")
            self.analyze_btn.setVisible(False)
            self.analyze_btn.setEnabled(False)
            return

        # No analysis result for this email
        self.verdict_badge.set_verdict(None)
        self.confidence_bar.set_confidence(None, "Confidence")
        self.time_label.setText("")
        self.model_used_label.setText(f"Model: {selected_model}")
        self.explanation_view.setText("—")
        self.explanation_card.setVisible(False)
        self.details_toggle.setVisible(False)
        self.text_agent.set_data(None, None, None)
        self.url_agent.set_data(None, None, None)
        self.meta_agent.set_data(None, None, None)

        # Set correct class badge to UNKNOWN when no analysis available
        self.correct_section.setVisible(True)
        is_dark = self.theme["name"] == "dark"
        if is_dark:
            bg, fg, border = "#374151", "#9ca3af", "#4b5563"
        else:
            bg, fg, border = "#f1f5f9", "#64748b", "#e2e8f0"
        self.true_badge.setText("UNKNOWN")
        self.true_badge.setStyleSheet(
            f"background: {bg}; color: {fg}; border: 1px solid {border};"
            "font-size: 22px; font-weight: 700; border-radius: 8px; padding: 12px;"
        )

        if in_progress:
            self.analyze_btn.setVisible(False)
            self.analyze_btn.setEnabled(False)
        else:
            self.analyze_btn.setText("Analyze Email")
            self.analyze_btn.setVisible(True)
            self.analyze_btn.setEnabled(True)

        if (
            email.is_analyzed
            and email.model
            and email.model.strip().lower() != selected_model
        ):
            self.model_used_label.setText(
                f"Model: {selected_model} (previous analysis: {email.model})"
            )

    def _clear_detail_panels(self) -> None:
        self.viewer_title.setText("Select an email")
        self.metadata_view.clear()
        self.body_view.clear()
        self.verdict_badge.set_verdict(None)
        self.confidence_bar.set_confidence(None)
        self.time_label.setText("")
        self.model_used_label.setText("")
        self.explanation_view.setText("—")
        self.explanation_card.setVisible(False)
        self.details_toggle.setVisible(False)
        self.remove_btn.setVisible(False)
        self.analyze_btn.setVisible(False)
        self.text_agent.set_data(None, None, None)
        self.url_agent.set_data(None, None, None)
        self.meta_agent.set_data(None, None, None)
        self.analyze_btn.setEnabled(False)

        # Ensure correct class badge shows "UNKNOWN"
        self.correct_section.setVisible(True)
        is_dark = self.theme["name"] == "dark"
        if is_dark:
            bg, fg, border = "#374151", "#9ca3af", "#4b5563"
        else:
            bg, fg, border = "#f1f5f9", "#64748b", "#e2e8f0"
        self.true_badge.setText("UNKNOWN")
        self.true_badge.setStyleSheet(
            f"background: {bg}; color: {fg}; border: 1px solid {border};"
            "font-size: 22px; font-weight: 700; border-radius: 8px; padding: 12px;"
        )

    def _insert_manual_email(self) -> None:
        dialog = EmailInputDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        body, metadata, label = dialog.get_email_data()
        if not body:
            QMessageBox.warning(self, "Missing Data", "Email body is required.")
            return

        # Determine next email_index
        all_emails = self.db.get_emails()  # all emails regardless of folder
        max_index = max([e.email_index for e in all_emails], default=0)
        new_index = max_index + 1

        # Insert into database
        self.db.insert_email(new_index, body, metadata, label)

        # Refresh UI
        self._refresh_email_list()
        self._refresh_statistics()
        self._update_analyze_all_button()
        self.status.showMessage(f"Email #{new_index} inserted manually.")

    def _on_link_clicked(self, url: QUrl) -> None:
        if self.current_email and self.current_email.trusted:
            open_external_url(url)

    def _trust_email(self) -> None:
        if not self.current_email or self.current_email.trusted:
            return
        reply = QMessageBox.question(
            self,
            "Trust Email",
            "This action will enable links contained in this email.\n\n"
            "AI predictions may be incorrect.\n\n"
            "Do you want to continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.db.set_trusted(self.current_email.id, True)
            self.current_email = self.db.get_email(self.current_email.id)
            if self.current_email:
                self._display_email(self.current_email)

    def _move_email(self) -> None:
        if not self.current_email:
            return
        prev = self.current_email.folder
        self.db.move_email(self.current_email.id, FOLDER_PHISHING)
        self._undo_stack.append(UndoAction(self.current_email.id, prev))
        self._refresh_email_list()
        self._refresh_statistics()
        self.status.showMessage("Email moved to Phishing Folder")

    def _restore_email(self) -> None:
        if not self.current_email:
            return
        prev = self.current_email.folder
        self.db.move_email(self.current_email.id, FOLDER_INBOX)
        self._undo_stack.append(UndoAction(self.current_email.id, prev))
        self._refresh_email_list()
        self._refresh_statistics()
        self.status.showMessage("Email restored to Inbox")

    def _remove_email(self) -> None:
        if not self.current_email:
            return
        reply = QMessageBox.question(
            self,
            "Remove Email",
            f"Delete email #{self.current_email.email_index} from the database?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.db.remove_email(self.current_email.id)
        self.current_email = None
        self._refresh_email_list()
        self._refresh_statistics()
        self._clear_detail_panels()
        self.status.showMessage("Email removed")

    def _undo_move(self) -> None:
        if not self._undo_stack:
            self.status.showMessage("Nothing to undo")
            return
        action = self._undo_stack.pop()
        self.db.move_email(action.email_id, action.previous_folder)
        if action.previous_folder != self.current_folder:
            self._switch_folder(action.previous_folder)
        else:
            self._refresh_email_list()
        self._refresh_statistics()
        self.status.showMessage("Undo successful")

    def _analyze_current(self) -> None:
        if not self.current_email:
            return
        email = self.current_email
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.setVisible(False)
        self.cancel_batch_btn.setVisible(True)
        self.cancel_batch_btn.setEnabled(True)
        self.single_progress.setVisible(True)
        self.single_progress.setRange(0, 0)
        self.status.showMessage(f"Analyzing email #{email.email_index}…")

        model_name = "gemma2_9b"
        self._analyzer.set_model(model_name)
        queued = self._analyzer.analyze_single(
            email.id, email.body, email.metadata, model_name
        )
        if not queued:
            self.analyze_btn.setEnabled(True)
            self.analyze_btn.setVisible(
                not self._has_result_for_selected_model(self.current_email)
            )
            self.cancel_batch_btn.setVisible(False)
            self.single_progress.setVisible(False)
            QMessageBox.warning(
                self, "Busy", "An analysis is already in progress. Please wait."
            )

    def _toggle_agent_details(self, checked: bool) -> None:
        self.details_toggle.setArrowType(
            Qt.ArrowType.DownArrow if checked else Qt.ArrowType.RightArrow
        )
        self.confidence_bar.setVisible(checked)
        self.agents_group.setVisible(checked)

    def _on_analyzer_busy(self, busy: bool) -> None:
        self._update_list_progress()
        self._update_analyze_all_button()
        if self.current_email:
            self._display_analysis(self.current_email)
        if not busy:
            if not self._analyzer.is_batch_active:
                self.cancel_batch_btn.setVisible(False)
            self.single_progress.setVisible(False)

    def _on_analyzer_status(self, message: str) -> None:
        self.status.showMessage(message)

    def _on_analysis_done(self, email_id: int, result: dict, elapsed: float) -> None:
        if not self._analyzer.is_busy():
            if not self._analyzer.is_batch_active:
                self.cancel_batch_btn.setVisible(False)
        self.db.save_analysis(email_id, result, elapsed)
        self._refresh_email_list()
        self._refresh_statistics()
        self._update_analyze_all_button()
        if self.current_email:
            self.current_email = self.db.get_email(self.current_email.id)
            if self.current_email:
                self._display_analysis(self.current_email)
        self.status.showMessage(f"Analysis complete ({elapsed:.2f}s)")

    def _on_analysis_error(self, email_id: int, message: str) -> None:
        if not self._analyzer.is_busy():
            if not self._analyzer.is_batch_active:
                self.cancel_batch_btn.setVisible(False)
        self._update_list_progress()
        self._update_analyze_all_button()
        QMessageBox.critical(self, "Analysis Error", message)
        self.status.showMessage("Analysis failed")

    def _remove_all_emails(self) -> None:
        reply = QMessageBox.question(
            self,
            "Remove All Emails",
            "Delete every email from the database? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.db.clear_all_emails()
        self.current_email = None
        self._refresh_email_list()
        self._refresh_statistics()
        self._update_analyze_all_button()
        self._clear_detail_panels()
        self.status.showMessage("All emails removed")

    def _analyze_all(self) -> None:
        if self._analyzer.is_batch_active:
            self._analyzer.cancel_batch()
            return

        if self._analyzer.is_busy():
            QMessageBox.warning(
                self, "Busy", "An analysis is already in progress. Please wait."
            )
            return

        emails = self.db.get_unanalyzed_emails()
        if not emails:
            self._update_analyze_all_button()
            return

        model_name = "gemma2_9b"
        self._analyzer.set_model(model_name)
        self.single_progress.setVisible(False)
        self.cancel_batch_btn.setVisible(False)
        self.batch_progress.setVisible(True)
        self.batch_label.setVisible(True)
        self.batch_progress.setMaximum(len(emails))
        self.batch_progress.setValue(0)
        self.batch_label.setText(f"Analyzing 0 / {len(emails)}")

        started = self._analyzer.analyze_batch(emails, model_name)
        if not started:
            self._reset_batch_ui()
            QMessageBox.warning(
                self, "Busy", "Could not start batch analysis. Please try again."
            )
            return

        self._update_analyze_all_button()
        self._update_list_progress()
        self.status.showMessage(f"Batch analysis: 0 / {len(emails)}")

    def _on_batch_progress(self, current: int, total: int, email_id: int) -> None:
        self.batch_progress.setMaximum(total)
        self.batch_progress.setValue(current)
        self.batch_label.setText(f"Analyzing {current} / {total}")
        self.status.showMessage(f"Batch analysis: {current} / {total}")
        self._update_list_progress()

    def _on_batch_finished(self) -> None:
        self._reset_batch_ui()
        self._update_analyze_all_button()
        self._update_list_progress()
        self.status.showMessage("Batch analysis complete")

    def _on_batch_cancelled(self) -> None:
        self._reset_batch_ui()
        self._update_analyze_all_button()
        self._update_list_progress()
        self.status.showMessage("Batch analysis cancelled")

    def _cancel_analysis(self) -> None:
        self._analyzer.cancel_current()

    def _cancel_batch(self) -> None:
        self._cancel_analysis()

    def _reset_batch_ui(self) -> None:
        self.cancel_batch_btn.setVisible(False)
        self.batch_progress.setVisible(False)
        self.batch_label.setVisible(False)

    def _import_csv(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import CSV Dataset",
            str(Path.home()),
            "CSV Files (*.csv)",
        )
        if not path:
            return

        result = import_csv(self.db, Path(path))
        if result.errors and result.imported == 0:
            QMessageBox.critical(self, "Import Failed", "\n".join(result.errors))
            return

        self._refresh_email_list()
        self._refresh_statistics()
        self._update_analyze_all_button()
        msg = f"Imported {result.imported} email(s)."
        if result.skipped:
            msg += f" Skipped {result.skipped} duplicate(s)."
        if result.errors:
            msg += f"\n\nWarnings:\n" + "\n".join(result.errors[:5])
        QMessageBox.information(self, "Import Complete", msg)
        self.status.showMessage(msg)

    def _export_results(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis Results",
            str(Path.home() / "analysis_results.csv"),
            "CSV Files (*.csv)",
        )
        if not path:
            return
        count = export_results(self.db, Path(path))
        if count == 0:
            QMessageBox.warning(self, "Export", "No analyzed emails to export.")
            return
        QMessageBox.information(
            self, "Export Complete", f"Exported {count} result(s) to:\n{path}"
        )

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About Multi LLMs",
            "<h3>Multi LLMs</h3>"
            "<p>Multi-Agent AI Phishing Detection System</p>"
            "<p>Demonstrates offline phishing detection using text, URL, and "
            "metadata agents with Dempster-Shafer evidence fusion.</p>"
            "<p>All analysis runs locally via <code>analyzer.py</code>.</p>",
        )

    def closeEvent(self, event) -> None:
        self._analyzer.shutdown()
        self.db.close()
        super().closeEvent(event)