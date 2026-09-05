import sys
from pathlib import Path

from PySide6.QtCore import QProcess, Qt
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTextEdit,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)


class AdexaGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("ADEXA — Adaptive Security Testing")
        self.resize(1100, 720)

        self.setStyleSheet("""
            QMainWindow {
                background: #f7fbff;
            }

            QLabel {
                color: #16324f;
            }

            #sidebar {
                background: #eaf5ff;
                border-right: 1px solid #d4e8f7;
            }

            #logo {
                color: #1976d2;
                font-size: 28px;
                font-weight: bold;
            }

            #subtitle {
                color: #6b849c;
                font-size: 12px;
            }

            #navButton {
                background: transparent;
                color: #315b7d;
                border: none;
                border-radius: 8px;
                padding: 11px;
                text-align: left;
                font-size: 14px;
            }

            #navButton:hover {
                background: #dcefff;
            }

            #navButtonActive {
                background: #d5ebfc;
                color: #1976d2;
                border: none;
                border-radius: 8px;
                padding: 11px;
                text-align: left;
                font-size: 14px;
                font-weight: bold;
            }

            #title {
                color: #16324f;
                font-size: 26px;
                font-weight: bold;
            }

            #description {
                color: #6b849c;
                font-size: 13px;
            }

            #card {
                background: white;
                border: 1px solid #dcecf8;
                border-radius: 12px;
            }

            #cardTitle {
                color: #16324f;
                font-size: 15px;
                font-weight: bold;
            }

            #statNumber {
                color: #1976d2;
                font-size: 28px;
                font-weight: bold;
            }

            #statLabel {
                color: #6b849c;
                font-size: 12px;
            }

            QLineEdit, QComboBox {
                background: white;
                border: 1px solid #c9deed;
                border-radius: 7px;
                padding: 9px;
                color: #16324f;
                font-size: 13px;
            }

            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #5aa9e6;
            }

            QPushButton#primaryButton {
                background: #1976d2;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 11px 18px;
                font-weight: bold;
            }

            QPushButton#primaryButton:hover {
                background: #1565c0;
            }

            #step {
                background: #f4f9fd;
                border: 1px solid #dcecf8;
                border-radius: 8px;
            }

            #result {
                background: #f1fbf5;
                border: 1px solid #ccebd8;
                border-radius: 10px;
            }

            #statusReady {
                color: #26834a;
                font-size: 12px;
            }

            #resultOutput {
                background: #f8fcff;
                border: 1px solid #dcecf8;
                border-radius: 7px;
                color: #315b7d;
                font-size: 12px;
                padding: 8px;
            }

            #muted {
                color: #9fc1d9;
                font-size: 12px;
            }

            #runDetailsTitle {
                color: #dff6ff;
                font-size: 30px;
                font-weight: bold;
            }

            #runDetailsCard {
                background: #1f293b;
                border: 1px solid #33445f;
                border-radius: 12px;
            }

            #runDetailsCard QLabel {
                color: #dff6ff;
                font-size: 14px;
            }

            #runDetailsCard #muted {
                color: #9fc1d9;
                font-size: 13px;
            }

            #runDetailsCard QPushButton {
                color: #dff6ff;
            }

            #technicalButton {
                background: #1976d2;
                color: white;
                border: 1px solid #2d8cff;
                border-radius: 8px;
                padding: 11px 16px;
                font-size: 13px;
                font-weight: bold;
            }

            #technicalButton:hover {
                background: #2585e5;
            }

            #technicalButton:pressed {
                background: #1265b5;
            }
        """)

        self.process = None
        self.stage_labels = []
        self.stage_frames = []
        self.stage_details = []
        self.build_ui()

    def build_ui(self):
        root = QWidget()
        main_layout = QHBoxLayout(root)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ================= SIDEBAR =================

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)

        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(20, 28, 20, 22)
        sidebar_layout.setSpacing(5)

        logo = QLabel("ADEXA")
        logo.setObjectName("logo")

        subtitle = QLabel("Adaptive Security Testing")
        subtitle.setObjectName("subtitle")

        sidebar_layout.addWidget(logo)
        sidebar_layout.addWidget(subtitle)
        sidebar_layout.addSpacing(30)

        self.nav_buttons = {}

        for name in ["Dashboard", "New Test", "Test History", "Settings"]:
            button = QPushButton(name)
            button.setObjectName("navButton")
            button.clicked.connect(
                lambda checked=False, page=name: self.change_page(page)
            )

            self.nav_buttons[name] = button
            sidebar_layout.addWidget(button)

        sidebar_layout.addStretch()

        status = QLabel("● System Ready")
        status.setObjectName("statusReady")

        sidebar_layout.addWidget(status)

        # ================= PAGES =================

        self.pages = QStackedWidget()

        self.dashboard_page = self.create_dashboard_page()
        self.new_test_page = self.create_new_test_page()
        self.history_page = self.create_history_page()
        self.details_page = self.create_details_page()
        self.settings_page = self.create_settings_page()

        self.pages.addWidget(self.dashboard_page)
        self.pages.addWidget(self.new_test_page)
        self.pages.addWidget(self.history_page)
        self.pages.addWidget(self.details_page)
        self.pages.addWidget(self.settings_page)

        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.pages)

        self.setCentralWidget(root)

        self.change_page("Dashboard")

    # ================= NAVIGATION =================

    def change_page(self, page_name):
        page_index = {
            "Dashboard": 0,
            "New Test": 1,
            "Test History": 2,
            "Run Details": 3,
            "Settings": 4,
        }

        self.pages.setCurrentIndex(page_index[page_name])

        for name, button in self.nav_buttons.items():
            button.setObjectName(
                "navButtonActive" if name == page_name else "navButton"
            )
            button.style().unpolish(button)
            button.style().polish(button)

    # ================= DASHBOARD =================

    def create_dashboard_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(35, 30, 35, 30)
        layout.setSpacing(20)

        title = QLabel("Dashboard")
        title.setStyleSheet("color: #dff6ff;")

        description = QLabel(
            "Overview of your ADEXA security-testing environment."
        )
        description.setObjectName("description")

        layout.addWidget(title)
        layout.addWidget(description)

        # Stats
        stats = QHBoxLayout()
        stats.setSpacing(15)

        stats_data = [
            ("0", "Tests Run"),
            ("0", "Verified Repairs"),
            ("0", "Failed Tests"),
        ]

        for number, label_text in stats_data:
            card = QFrame()
            card.setObjectName("card")

            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(20, 18, 20, 18)

            number_label = QLabel(number)
            number_label.setObjectName("statNumber")

            label = QLabel(label_text)
            label.setObjectName("statLabel")

            card_layout.addWidget(number_label)
            card_layout.addWidget(label)

            stats.addWidget(card)

        layout.addLayout(stats)

        # Environment
        environment = QFrame()
        environment.setObjectName("card")

        env_layout = QVBoxLayout(environment)
        env_layout.setContentsMargins(22, 20, 22, 20)

        env_title = QLabel("Environment")
        env_title.setObjectName("cardTitle")

        ready = QLabel("● Ready for authorized testing")
        ready.setObjectName("statusReady")

        env_description = QLabel(
            "ADEXA is configured for controlled DVWA SQL Injection testing."
        )
        env_description.setObjectName("muted")

        env_layout.addWidget(env_title)
        env_layout.addSpacing(8)
        env_layout.addWidget(ready)
        env_layout.addWidget(env_description)

        layout.addWidget(environment)

        # Quick action
        action = QFrame()
        action.setObjectName("card")

        action_layout = QHBoxLayout(action)
        action_layout.setContentsMargins(22, 18, 22, 18)

        action_text = QVBoxLayout()

        action_title = QLabel("Start a new security test")
        action_title.setObjectName("cardTitle")

        action_description = QLabel(
            "Configure an authorized target and let ADEXA analyze the result."
        )
        action_description.setObjectName("muted")

        action_text.addWidget(action_title)
        action_text.addWidget(action_description)

        new_test = QPushButton("NEW TEST")
        new_test.setObjectName("primaryButton")
        new_test.clicked.connect(lambda: self.change_page("New Test"))

        action_layout.addLayout(action_text)
        action_layout.addStretch()
        action_layout.addWidget(new_test)

        layout.addWidget(action)

        layout.addStretch()

        return page

    # ================= NEW TEST =================

    def create_new_test_page(self):
        page = QWidget()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(35, 30, 35, 30)
        layout.setSpacing(18)

        scroll.setWidget(content)

        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(scroll)

        title = QLabel("New Authorized Test")
        title.setObjectName("title")

        description = QLabel(
            "Configure a controlled security test using the ADEXA engine."
        )
        description.setObjectName("description")

        layout.addWidget(title)
        layout.addWidget(description)

        card = QFrame()
        card.setObjectName("card")

        grid = QGridLayout(card)
        grid.setContentsMargins(25, 22, 25, 22)
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(12)

        grid.addWidget(QLabel("Target URL"), 0, 0, 1, 2)

        self.target = QLineEdit()
        self.target.setPlaceholderText(
            "http://127.0.0.1:4280/vulnerabilities/sqli/"
        )

        grid.addWidget(self.target, 1, 0, 1, 2)

        grid.addWidget(QLabel("Parameter"), 2, 0)
        grid.addWidget(QLabel("Method"), 2, 1)

        self.parameter = QLineEdit("id")

        self.method = QComboBox()
        self.method.addItems(["GET"])

        grid.addWidget(self.parameter, 3, 0)
        grid.addWidget(self.method, 3, 1)

        grid.addWidget(QLabel("Initial Payload"), 4, 0, 1, 2)

        self.payload = QLineEdit()
        self.payload.setPlaceholderText("Enter starting payload")

        grid.addWidget(self.payload, 5, 0, 1, 2)

        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.start_button = QPushButton("START AUTHORIZED TEST")
        self.start_button.setObjectName("primaryButton")
        self.start_button.clicked.connect(self.start_test)

        button_layout.addWidget(self.start_button)

        grid.addLayout(button_layout, 6, 0, 1, 2)

        layout.addWidget(card)

        execution_title = QLabel("ADEXA Execution")
        execution_title.setObjectName("cardTitle")

        layout.addWidget(execution_title)

        steps = QHBoxLayout()
        steps.setSpacing(10)

        for number, name in [
            ("1", "Execute"),
            ("2", "Observe"),
            ("3", "Analyze"),
            ("4", "Repair"),
            ("5", "Verify"),
        ]:
            step = QFrame()
            step.setObjectName("step")

            step_layout = QVBoxLayout(step)
            step_layout.setContentsMargins(14, 12, 14, 12)
            step_layout.setSpacing(5)

            number_label = QLabel(number)
            number_label.setStyleSheet(
                "color: #1976d2; font-size: 18px; font-weight: bold;"
            )

            name_label = QLabel(name)
            name_label.setStyleSheet(
                "color: #315b7d; font-size: 12px; font-weight: bold;"
            )

            state_label = QLabel("Waiting")
            state_label.setObjectName("muted")

            detail_label = QLabel("")
            detail_label.setObjectName("muted")
            detail_label.setWordWrap(True)

            step_layout.addWidget(number_label)
            step_layout.addWidget(name_label)
            step_layout.addWidget(state_label)
            step_layout.addWidget(detail_label)

            self.stage_labels.append(state_label)
            self.stage_frames.append(step)
            self.stage_details.append(detail_label)

            steps.addWidget(step)

        layout.addLayout(steps)

        result = QFrame()
        result.setObjectName("result")

        result_layout = QVBoxLayout(result)
        result_layout.setContentsMargins(20, 16, 20, 16)
        result_layout.setSpacing(10)

        result_title = QLabel("RESULT")
        result_title.setStyleSheet(
            "color: #26834a; font-size: 13px; font-weight: bold;"
        )

        self.result_status = QLabel("No test has been started yet.")
        self.result_status.setStyleSheet(
            "color: #dff6ff; font-size: 22px; font-weight: bold;"
        )

        self.result_description = QLabel(
            "Run an authorized test to see the result."
        )
        self.result_description.setStyleSheet(
            "color: #9fc1d9; font-size: 13px;"
        )
        self.result_description.setWordWrap(True)

        info_layout = QGridLayout()
        info_layout.setHorizontalSpacing(30)
        info_layout.setVerticalSpacing(8)

        original_title = QLabel("Original payload")
        original_title.setObjectName("muted")

        self.original_payload_label = QLabel("—")
        self.original_payload_label.setWordWrap(True)

        repaired_title = QLabel("Repaired payload")
        repaired_title.setObjectName("muted")

        self.repaired_payload_label = QLabel("—")
        self.repaired_payload_label.setWordWrap(True)

        verification_title = QLabel("Verification")
        verification_title.setObjectName("muted")

        self.verification_label = QLabel("—")

        info_layout.addWidget(original_title, 0, 0)
        info_layout.addWidget(self.original_payload_label, 1, 0)
        info_layout.addWidget(repaired_title, 0, 1)
        info_layout.addWidget(self.repaired_payload_label, 1, 1)
        info_layout.addWidget(verification_title, 2, 0)
        info_layout.addWidget(self.verification_label, 3, 0)

        self.result_text = QTextEdit()
        self.result_text.setObjectName("resultOutput")
        self.result_text.setReadOnly(True)
        self.result_text.setFixedHeight(180)
        self.result_text.setPlainText("No technical output yet.")
        self.result_text.hide()

        self.details_button = QPushButton("View technical details")
        self.details_button.setObjectName("technicalButton")
        self.details_button.clicked.connect(self.toggle_details)

        result_layout.addWidget(result_title)
        result_layout.addWidget(self.result_status)
        result_layout.addWidget(self.result_description)
        result_layout.addLayout(info_layout)
        result_layout.addWidget(self.details_button)
        result_layout.addWidget(self.result_text)

        layout.addWidget(result)
        layout.addStretch()

        return page

    # ================= HISTORY =================

    def create_history_page(self):
        page = QWidget()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(35, 30, 35, 30)
        layout.setSpacing(18)

        title = QLabel("Test History")
        title.setObjectName("title")

        description = QLabel(
            "Review previous ADEXA security-testing runs."
        )
        description.setObjectName("description")

        layout.addWidget(title)
        layout.addWidget(description)

        runs_dir = Path(__file__).resolve().parent / "runs"

        run_dirs = sorted(
            [
                d for d in runs_dir.iterdir()
                if d.is_dir()
            ],
            reverse=True,
        ) if runs_dir.exists() else []

        displayed = 0

        for run_dir in run_dirs[:20]:
            try:
                import json

                poc_file = (
                    run_dir
                    / "files"
                    / "poc_spec_final.json"
                )

                if not poc_file.exists():
                    continue

                with open(poc_file, "r") as f:
                    poc = json.load(f)

                iterations = sorted(
                    run_dir.glob("iter_*.json")
                )

                if not iterations:
                    continue

                with open(iterations[-1], "r") as f:
                    final_data = json.load(f)

                state = final_data.get("state", {})

                verified_payload = (
                    state.get("verified_exploit_payload")
                    or state.get("selected_payload")
                    or "—"
                )

                original_payload = (
                    poc.get("adexa_cli", {})
                    .get("starting_payload")
                    or "—"
                )

                base_url = poc.get("base_url", "—")

                target_path = ""
                for step in poc.get("steps", []):
                    if step.get("id") == "sqli_page":
                        target_path = step.get("path", "")
                        break

                target_url = (
                    base_url.rstrip("/") + target_path
                    if target_path
                    else base_url
                )

                status = (
                    "Success"
                    if state.get("verified_exploit_payload")
                    else "Failed"
                )

                card = QFrame()
                card.setObjectName("card")

                card_layout = QVBoxLayout(card)
                card_layout.setContentsMargins(22, 18, 22, 18)
                card_layout.setSpacing(8)

                status_label = QLabel(
                    "✓ Success"
                    if status == "Success"
                    else "✗ Failed"
                )

                status_label.setStyleSheet(
                    "color: #26834a; font-weight: bold; font-size: 16px;"
                    if status == "Success"
                    else "color: #c62828; font-weight: bold; font-size: 16px;"
                )

                run_label = QLabel(
                    f"Run ID: {run_dir.name}"
                )
                run_label.setObjectName("muted")
                run_label.setWordWrap(True)

                card_layout.addWidget(status_label)
                card_layout.addWidget(run_label)

                target_label = QLabel(
                    f"Target: {target_url}"
                )
                target_label.setObjectName("muted")
                target_label.setWordWrap(True)

                original_label = QLabel(
                    f"Original payload: {original_payload}"
                )
                original_label.setWordWrap(True)

                repaired_label = QLabel(
                    f"Repaired payload: {verified_payload}"
                )
                repaired_label.setWordWrap(True)

                verification_label = QLabel(
                    "✓ Vulnerability verified"
                    if status == "Success"
                    else "✗ Verification failed"
                )

                verification_label.setStyleSheet(
                    "color: #26834a; font-weight: bold;"
                    if status == "Success"
                    else "color: #c62828; font-weight: bold;"
                )

                card_layout.addWidget(target_label)
                card_layout.addWidget(original_label)
                card_layout.addWidget(repaired_label)
                card_layout.addWidget(verification_label)

                view_button = QPushButton("View Details")
                view_button.setObjectName("navButton")
                view_button.clicked.connect(
                    lambda checked=False, path=str(run_dir):
                    self.show_run_details(path)
                )

                card_layout.addWidget(view_button)

                layout.addWidget(card)
                displayed += 1

            except Exception:
                continue

        if displayed == 0:
            card = QFrame()
            card.setObjectName("card")

            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(22, 22, 22, 22)

            empty = QLabel(
                "No completed tests have been recorded yet."
            )
            empty.setObjectName("muted")

            card_layout.addWidget(empty)
            layout.addWidget(card)

        layout.addStretch()

        scroll.setWidget(content)

        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(scroll)

        return page

    # ================= RUN DETAILS =================

    def create_details_page(self):
        page = QWidget()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(35, 30, 35, 30)
        layout.setSpacing(18)

        back_button = QPushButton("← Back to Test History")
        back_button.setStyleSheet(
            "color: #4da3ff; font-size: 14px; font-weight: bold;"
        )
        back_button.clicked.connect(
            lambda: self.change_page("Test History")
        )

        layout.addWidget(back_button)

        self.details_title = QLabel("Run Details")
        self.details_title.setObjectName("title")
        self.details_title.setStyleSheet(
            "color: #e8f1ff; font-size: 32px; font-weight: bold;"
        )
        layout.addWidget(self.details_title)

        self.details_run_id = QLabel("Run ID: —")
        self.details_run_id.setObjectName("muted")
        layout.addWidget(self.details_run_id)

        card = QFrame()
        card.setObjectName("runDetailsCard")

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(22, 20, 22, 20)
        card_layout.setSpacing(10)

        self.details_status = QLabel("—")
        self.details_status.setStyleSheet(
            "font-size: 18px; font-weight: bold;"
        )

        self.details_target = QLabel("Target: —")
        self.details_target.setWordWrap(True)

        self.details_original = QLabel(
            "Original payload: —"
        )
        self.details_original.setWordWrap(True)

        self.details_repaired = QLabel(
            "Repaired payload: —"
        )
        self.details_repaired.setWordWrap(True)

        self.details_strategy = QLabel(
            "Strategy: —"
        )

        self.details_verification = QLabel(
            "Verification: —"
        )

        self.details_ai = QLabel(
            "AI decision: —"
        )
        self.details_ai.setWordWrap(True)

        card_layout.addWidget(self.details_status)
        card_layout.addWidget(self.details_target)
        card_layout.addWidget(self.details_original)
        card_layout.addWidget(self.details_repaired)
        card_layout.addWidget(self.details_strategy)
        card_layout.addWidget(self.details_verification)
        card_layout.addWidget(self.details_ai)

        layout.addWidget(card)

        execution_title = QLabel("Execution")
        execution_title.setStyleSheet(
            "color: #e8f1ff; font-size: 22px; font-weight: bold;"
        )
        layout.addWidget(execution_title)

        self.details_execution = QLabel(
            "Execute → Observe → Analyze → Repair → Verify"
        )
        self.details_execution.setWordWrap(True)
        self.details_execution.setStyleSheet(
            """
            color: #e8f1ff;
            background: #17243a;
            border: 1px solid #3d6b9e;
            border-radius: 10px;
            padding: 16px;
            font-size: 16px;
            font-weight: bold;
            """
        )
        layout.addWidget(self.details_execution)

        technical_title = QLabel("Technical Output")
        technical_title.setStyleSheet(
            "color: #e8f1ff; font-size: 22px; font-weight: bold;"
        )
        layout.addWidget(technical_title)

        self.details_output = QTextEdit()
        self.details_output.setObjectName("resultOutput")
        self.details_output.setReadOnly(True)
        self.details_output.setMinimumHeight(220)
        self.details_output.hide()

        self.details_toggle = QPushButton(
            "View raw technical output"
        )
        self.details_toggle.setObjectName("navButton")
        self.details_toggle.clicked.connect(
            self.toggle_details_output
        )

        layout.addWidget(self.details_toggle)
        layout.addWidget(self.details_output)
        layout.addStretch()

        scroll.setWidget(content)

        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(scroll)

        return page


    def toggle_details_output(self):
        if self.details_output.isVisible():
            self.details_output.hide()
            self.details_toggle.setText(
                "View raw technical output"
            )
        else:
            self.details_output.show()
            self.details_toggle.setText(
                "Hide raw technical output"
            )


    def show_run_details(self, run_dir):
        import json

        run_dir = Path(run_dir)

        poc_file = (
            run_dir
            / "files"
            / "poc_spec_final.json"
        )

        iterations = sorted(
            run_dir.glob("iter_*.json")
        )

        if not poc_file.exists() or not iterations:
            return

        with open(poc_file, "r") as f:
            poc = json.load(f)

        with open(iterations[-1], "r") as f:
            final_data = json.load(f)

        state = final_data.get("state", {})

        base_url = poc.get("base_url", "—")

        target_path = ""
        for step in poc.get("steps", []):
            if step.get("id") == "sqli_page":
                target_path = step.get("path", "")
                break

        target_url = (
            base_url.rstrip("/") + target_path
            if target_path
            else base_url
        )

        original = (
            poc.get("adexa_cli", {})
            .get("starting_payload")
            or "—"
        )

        repaired = (
            state.get("verified_exploit_payload")
            or state.get("selected_payload")
            or "—"
        )

        success = bool(
            state.get("verified_exploit_payload")
        )

        strategy = (
            state.get("strategy_used")
            or "—"
        )

        ai_reason = (
            state.get("ai_reason")
            or "—"
        )

        self.details_title.setText(
            "Run Details"
        )
        self.details_run_id.setText(
            f"Run ID: {run_dir.name}"
        )

        self.details_status.setText(
            "✓ TEST SUCCESSFUL"
            if success
            else "✗ TEST FAILED"
        )

        self.details_status.setStyleSheet(
            "color: #26834a; font-size: 18px; font-weight: bold;"
            if success
            else "color: #c62828; font-size: 18px; font-weight: bold;"
        )

        self.details_target.setText(
            f"Target: {target_url}"
        )

        self.details_original.setText(
            f"Original payload: {original}"
        )

        self.details_repaired.setText(
            f"Repaired payload: {repaired}"
        )

        self.details_strategy.setText(
            f"Strategy: {strategy}"
        )

        self.details_verification.setText(
            "Verification: ✓ Verified"
            if success
            else "Verification: ✗ Not verified"
        )

        self.details_ai.setText(
            f"AI decision: {ai_reason}"
        )

        self.details_execution.setText(
            "✓  Execute     →     ✓  Observe     →     ✓  Analyze     →     "
            "✓  Repair     →     "
            + ("✓  Verify" if success else "✗  Verify")
        )

        self.details_execution.setStyleSheet(
            """
            color: #e8f1ff;
            background: #17243a;
            border: 1px solid #3d6b9e;
            border-radius: 10px;
            padding: 16px;
            font-size: 16px;
            font-weight: bold;
            """
        )
        self.details_execution.setAlignment(Qt.AlignCenter)

        output_lines = []

        for iteration in iterations:
            try:
                with open(iteration, "r") as f:
                    data = json.load(f)

                output_lines.append(
                    f"{iteration.name}\n"
                    + json.dumps(
                        data,
                        indent=2
                    )
                )
            except Exception:
                continue

        self.details_output.setPlainText(
            "\n\n".join(output_lines)
        )

        self.change_page("Run Details")

    # ================= SETTINGS =================

    def create_settings_page(self):
        page = QWidget()

        layout = QVBoxLayout(page)
        layout.setContentsMargins(35, 30, 35, 30)
        layout.setSpacing(18)

        title = QLabel("Settings")
        title.setObjectName("title")

        description = QLabel(
            "Configure the ADEXA user interface and local environment."
        )
        description.setObjectName("description")

        layout.addWidget(title)
        layout.addWidget(description)

        card = QFrame()
        card.setObjectName("card")

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(22, 22, 22, 22)

        security = QLabel("Authorized testing")
        security.setObjectName("cardTitle")

        security_info = QLabel(
            "ADEXA is intended for authorized security testing "
            "in controlled environments."
        )
        security_info.setObjectName("muted")
        security_info.setWordWrap(True)

        card_layout.addWidget(security)
        card_layout.addSpacing(8)
        card_layout.addWidget(security_info)

        layout.addWidget(card)
        layout.addStretch()

        return page

    # ================= TEST =================

    def toggle_details(self):
        if self.result_text.isVisible():
            self.result_text.hide()
            self.details_button.setText("View technical details")
        else:
            self.result_text.show()
            self.details_button.setText("Hide technical details")


    def start_test(self):
        target = self.target.text().strip()
        parameter = self.parameter.text().strip()
        payload = self.payload.text().strip()

        if not target:
            self.result_text.setPlainText(
                "Please enter a target URL."
            )
            return

        if not parameter:
            self.result_text.setPlainText(
                "Please enter an injection parameter."
            )
            return

        if not payload:
            self.result_text.setPlainText(
                "Please enter an initial payload."
            )
            return

        if self.process is not None:
            return

        self.result_text.setPlainText(
            "Starting ADEXA..."
        )

        self.start_button.setEnabled(False)

        self.process = QProcess(self)

        self.process.setProcessChannelMode(
            QProcess.MergedChannels
        )

        self.process.setWorkingDirectory(
            str(Path(__file__).resolve().parent)
        )

        self.process.readyReadStandardOutput.connect(
            self.read_process_output
        )

        self.process.readyReadStandardError.connect(
            self.read_process_output
        )

        self.process.finished.connect(
            self.process_finished
        )

        command = "python3"

        arguments = [
            "-u",
            "adexa.py",
            "--url",
            target,
            "--param",
            parameter,
            "--payload",
            payload,
            "--method",
            self.method.currentText(),
        ]

        self.process.start(command, arguments)

    def read_process_output(self):
        if self.process is None:
            return

        output = bytes(
            self.process.readAll()
        ).decode("utf-8", errors="replace")

        if not output.strip():
            return

        current = self.result_text.toPlainText()

        if current in ("Starting ADEXA...", ""):
            current = ""

        text = (current + "\n" + output.strip()).strip()

        self.result_text.setPlainText(text)

        # Update the execution stages from ADEXA output.
        if "Execute ✓" in text:
            self.set_stage(0, "Complete", "Test executed")
        elif "Execute" in text:
            self.set_stage(0, "Running", "Executing test")

        if "Observe ✓" in text:
            self.set_stage(1, "Complete", "Response observed")
        elif "Observe" in text:
            self.set_stage(1, "Running", "Observing target")

        if "Analyze ✓" in text:
            self.set_stage(2, "Complete", "Failure analyzed")
        elif "Analyze" in text:
            self.set_stage(2, "Running", "Analyzing result")

        if "Repair →" in text:
            repair_line = next(
                (
                    line.strip()
                    for line in text.splitlines()
                    if "Repair →" in line
                ),
                "Repair selected",
            )
            payload = repair_line.split("Repair →", 1)[-1].strip()
            self.set_stage(3, "Complete", payload)
        elif "Repair" in text:
            self.set_stage(3, "Running", "Selecting repair")

        if "Verify ✓" in text:
            self.set_stage(4, "Verified", "Vulnerability verified")
        elif "Verify ✗" in text:
            self.set_stage(4, "Failed", "Verification failed")
        elif "Verify" in text:
            self.set_stage(4, "Running", "Verifying repair")

    def set_stage(self, index, state, detail=""):
        if index < 0 or index >= len(self.stage_labels):
            return

        label = self.stage_labels[index]
        frame = self.stage_frames[index]
        detail_label = self.stage_details[index]

        label.setText(state)
        detail_label.setText(detail)

        if state == "Running":
            frame.setObjectName("stepActive")
            label.setStyleSheet(
                "color: #1976d2; font-size: 12px; font-weight: bold;"
            )
        elif state in ("Complete", "Verified"):
            frame.setObjectName("stepComplete")
            label.setStyleSheet(
                "color: #26834a; font-size: 12px; font-weight: bold;"
            )
        elif state == "Failed":
            frame.setObjectName("stepFailed")
            label.setStyleSheet(
                "color: #c62828; font-size: 12px; font-weight: bold;"
            )
        else:
            frame.setObjectName("step")
            label.setObjectName("muted")

        frame.style().unpolish(frame)
        frame.style().polish(frame)
        frame.update()


    def process_finished(self, exit_code, exit_status):
        self.start_button.setEnabled(True)

        output = self.result_text.toPlainText()

        original_payload = self.payload.text().strip()

        repaired_payload = "—"
        for line in output.splitlines():
            if "[ADEXA] Final Payload:" in line:
                repaired_payload = line.split(
                    "[ADEXA] Final Payload:", 1
                )[-1].strip()
                break

        if "[ADEXA] Status: Success" in output:
            self.result_status.setText("✓ TEST SUCCESSFUL")
            self.result_status.setStyleSheet(
                "color: #26834a; font-size: 18px; font-weight: bold;"
            )
            self.result_description.setText(
                "ADEXA successfully verified the repair."
            )
            self.verification_label.setText("✓ Vulnerability verified")
            self.verification_label.setStyleSheet(
                "color: #26834a; font-weight: bold;"
            )

        elif "[ADEXA] Status: Failed" in output:
            self.result_status.setText("✗ TEST FAILED")
            self.result_status.setStyleSheet(
                "color: #c62828; font-size: 18px; font-weight: bold;"
            )
            self.result_description.setText(
                "ADEXA could not verify a successful repair."
            )
            self.verification_label.setText("✗ Verification failed")
            self.verification_label.setStyleSheet(
                "color: #c62828; font-weight: bold;"
            )

        elif exit_code != 0:
            self.result_status.setText("✗ EXECUTION ERROR")
            self.result_status.setStyleSheet(
                "color: #c62828; font-size: 18px; font-weight: bold;"
            )
            self.result_description.setText(
                "ADEXA encountered an execution error."
            )
            self.verification_label.setText("—")

        else:
            self.result_status.setText("✓ EXECUTION COMPLETED")
            self.result_description.setText(
                "ADEXA completed the authorized test."
            )

        self.original_payload_label.setText(
            original_payload or "—"
        )
        self.repaired_payload_label.setText(
            repaired_payload
        )

        self.result_text.hide()
        self.details_button.setText("View technical details")

        self.process = None



def main():
    app = QApplication(sys.argv)

    window = AdexaGUI()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
