import sys
import os
import json
import signal
import asyncio
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from PySide6 import QtCore, QtGui, QtWidgets

from yumi.core.engine import Engine


@dataclass
class ResultItem:
    file: str = ""
    secret: str = ""
    endpoint: str = ""
    line: int = 0
    severity: str = ""
    snippet: str = ""


RESULT_HEADERS = ["File", "Secret", "Endpoint", "Line", "Severity", "Snippet"]


class ResultTableModel(QtCore.QAbstractTableModel):
    def __init__(self, results: Optional[List[ResultItem]] = None, parent=None):
        super().__init__(parent)
        self._results: List[ResultItem] = results or []

    def rowCount(self, parent=QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._results)

    def columnCount(self, parent=QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(RESULT_HEADERS)

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._results)):
            return None
        item = self._results[index.row()]
        if role in (QtCore.Qt.DisplayRole, QtCore.Qt.EditRole):
            col = index.column()
            if col == 0:
                return item.file
            if col == 1:
                return item.secret
            if col == 2:
                return item.endpoint
            if col == 3:
                return str(item.line)
            if col == 4:
                return item.severity
            if col == 5:
                return item.snippet
        if role == QtCore.Qt.ToolTipRole:
            return item.snippet
        if role == QtCore.Qt.TextAlignmentRole and index.column() == 3:
            return QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter
        return None

    def headerData(self, section: int, orientation: QtCore.Qt.Orientation, role: int = QtCore.Qt.DisplayRole):
        if role != QtCore.Qt.DisplayRole:
            return None
        if orientation == QtCore.Qt.Horizontal:
            return RESULT_HEADERS[section]
        return section + 1

    def set_results(self, results: List[ResultItem]):
        self.beginResetModel()
        self._results = results
        self.endResetModel()

    def result_at(self, row: int) -> Optional[ResultItem]:
        if 0 <= row < len(self._results):
            return self._results[row]
        return None


class ResultFilterProxyModel(QtCore.QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._filter_text = ""
        self._severity_filter: Optional[str] = None
        self.setFilterCaseSensitivity(QtCore.Qt.CaseInsensitive)
        self.setFilterKeyColumn(-1)

    def set_filter_text(self, text: str):
        self._filter_text = text or ""
        self.invalidate()

    def set_severity_filter(self, severity: Optional[str]):
        self._severity_filter = severity
        self.invalidate()

    def filterAcceptsRow(self, source_row: int, source_parent: QtCore.QModelIndex) -> bool:
        src = self.sourceModel()
        if src is None:
            return True
        item_text_parts = []
        for col in range(src.columnCount()):
            idx = src.index(source_row, col, source_parent)
            val = src.data(idx, QtCore.Qt.DisplayRole) or ""
            item_text_parts.append(str(val))
        item_text = " ".join(item_text_parts)
        if self._filter_text and self._filter_text.lower() not in item_text.lower():
            return False
        if self._severity_filter:
            idx_sev = src.index(source_row, 4, source_parent)
            sev_val = src.data(idx_sev, QtCore.Qt.DisplayRole) or ""
            if str(sev_val).upper() != self._severity_filter.upper():
                return False
        return True


class ScanWorker(QtCore.QObject):
    finished = QtCore.Signal(bool, str)
    log = QtCore.Signal(str)
    results_ready = QtCore.Signal(list)

    def __init__(self, target: str, output_file: str, threads: int, user_agent: Optional[str] = None):
        super().__init__()
        self._target = target
        self._output_file = output_file
        self._threads = threads
        self._cancel_requested = False
        self._user_agent = user_agent

    @QtCore.Slot()
    def run(self):
        env_backup = os.environ.get("YUMI_USER_AGENT")
        if self._user_agent:
            os.environ["YUMI_USER_AGENT"] = self._user_agent
        self.log.emit(f"Starting scan: {self._target}")
        if self._user_agent:
            self.log.emit(f"Using User-Agent: {self._user_agent}")
        try:
            engine = Engine(self._target, self._output_file, self._threads)
            asyncio.run(engine.run())
            if self._cancel_requested:
                self.log.emit("Scan finished; cancel was requested, engine stops after current tasks.")
            if not os.path.exists(self._output_file):
                self.log.emit("No report file generated. Engine may have found no results.")
                self.results_ready.emit([])
                self.finished.emit(True, "")
                return
            try:
                with open(self._output_file, "r", encoding="utf-8") as f:
                    raw: Any = json.load(f)
            except Exception as e:
                self.log.emit(f"Error reading report file: {e}")
                self.results_ready.emit([])
                self.finished.emit(False, f"Failed to read report file: {e}")
                return
            if isinstance(raw, dict):
                raw_results: List[Dict[str, Any]] = raw.get("results", []) or raw.get("findings", []) or []
            else:
                raw_results = raw
            parsed: List[ResultItem] = []
            for r in raw_results:
                file_val = (
                    r.get("file")
                    or r.get("file_url")
                    or r.get("url")
                    or r.get("source")
                    or ""
                )
                secret_val = (
                    r.get("secret")
                    or r.get("rule_name")
                    or r.get("rule")
                    or r.get("type")
                    or ""
                )
                endpoint_val = r.get("endpoint") or r.get("endpoint_url") or ""
                line_val = r.get("line") or r.get("line_number") or r.get("lineno") or 0
                try:
                    line_val_int = int(line_val)
                except Exception:
                    line_val_int = 0
                severity_raw = r.get("severity") or r.get("level") or ""
                sev_map = {
                    "low": "LOW",
                    "medium": "MEDIUM",
                    "med": "MEDIUM",
                    "high": "HIGH",
                    "critical": "CRITICAL",
                }
                sev_key = str(severity_raw).strip().lower()
                severity_val = sev_map.get(sev_key, str(severity_raw).upper() if severity_raw else "")
                snippet_val = r.get("snippet") or r.get("match") or r.get("value") or ""
                parsed.append(
                    ResultItem(
                        file=str(file_val),
                        secret=str(secret_val),
                        endpoint=str(endpoint_val),
                        line=line_val_int,
                        severity=str(severity_val),
                        snippet=str(snippet_val),
                    )
                )
            self.results_ready.emit(parsed)
            self.finished.emit(True, "")
        except Exception as e:
            self.log.emit(f"Error during scan: {e}")
            self.finished.emit(False, str(e))
        finally:
            if env_backup is None:
                os.environ.pop("YUMI_USER_AGENT", None)
            else:
                os.environ["YUMI_USER_AGENT"] = env_backup

    def request_cancel(self):
        self._cancel_requested = True
        self.log.emit("Cancellation requested; engine will stop after current tasks.")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def handle_sigint(signal_received, frame):
    app = QtWidgets.QApplication.instance()
    if app is None:
        return
    windows = app.topLevelWidgets()
    for w in windows:
        if hasattr(w, "_worker") and w._worker:
            w._worker.request_cancel()
            if hasattr(w, "lbl_status"):
                w.lbl_status.setText("Ctrl+C detected – stopping scan…")
            if hasattr(w, "log_view"):
                from datetime import datetime, timezone
                w.log_view.appendPlainText(f"[{datetime.now(timezone.utc).isoformat()}] Ctrl+C detected, cancelling scan.")


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Yumi : GUI | Author : g0w6y")
        self.resize(1100, 700)
        self.setMinimumSize(900, 550)
        self._thread: Optional[QtCore.QThread] = None
        self._worker: Optional[ScanWorker] = None
        self._user_agents: List[str] = []
        self._current_user_agent: Optional[str] = None
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root_layout = QtWidgets.QVBoxLayout(central)
        root_layout.setContentsMargins(6, 6, 6, 6)
        root_layout.setSpacing(6)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        root_layout.addWidget(splitter)
        self._build_left_panel(splitter)
        self._build_right_panel(splitter)
        self._build_status_bar()
        self._build_menu()
        self._apply_dark_theme()

    def _build_left_panel(self, splitter: QtWidgets.QSplitter):
        left = QtWidgets.QFrame()
        left.setFrameShape(QtWidgets.QFrame.StyledPanel)
        left_layout = QtWidgets.QVBoxLayout(left)
        left_layout.setContentsMargins(12, 12, 12, 12)
        left_layout.setSpacing(12)
        title = QtWidgets.QLabel("Scan Configuration")
        font = title.font()
        font.setPointSize(font.pointSize() + 2)
        font.setBold(True)
        title.setFont(font)
        left_layout.addWidget(title)
        form = QtWidgets.QFormLayout()
        form.setLabelAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        self.input_target = QtWidgets.QLineEdit()
        self.input_target.setPlaceholderText("example.com or https://target.com/path")
        form.addRow("Target:", self.input_target)
        self.spin_threads = QtWidgets.QSpinBox()
        self.spin_threads.setRange(1, 128)
        self.spin_threads.setValue(20)
        form.addRow("Threads:", self.spin_threads)
        self.output_path = QtWidgets.QLineEdit("gui_report.json")
        form.addRow("Output file:", self.output_path)
        left_layout.addLayout(form)
        ua_layout = QtWidgets.QVBoxLayout()
        ua_header = QtWidgets.QLabel("User-Agent")
        ua_font = ua_header.font()
        ua_font.setBold(True)
        ua_header.setFont(ua_font)
        ua_layout.addWidget(ua_header)
        ua_row = QtWidgets.QHBoxLayout()
        self.ua_file_path = QtWidgets.QLineEdit()
        self.ua_file_path.setPlaceholderText("No file loaded")
        self.ua_file_path.setReadOnly(True)
        btn_browse_ua = QtWidgets.QPushButton("Load from file")
        ua_row.addWidget(self.ua_file_path)
        ua_row.addWidget(btn_browse_ua)
        ua_layout.addLayout(ua_row)
        self.chk_use_ua = QtWidgets.QCheckBox("Use random User-Agent from file")
        self.chk_use_ua.setEnabled(False)
        ua_layout.addWidget(self.chk_use_ua)
        self.lbl_current_ua = QtWidgets.QLabel("Current User-Agent: default")
        self.lbl_current_ua.setWordWrap(True)
        ua_layout.addWidget(self.lbl_current_ua)
        left_layout.addLayout(ua_layout)
        btn_row = QtWidgets.QHBoxLayout()
        btn_row.addStretch(1)
        self.btn_start = QtWidgets.QPushButton("Start scan")
        self.btn_start.setIcon(self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_MediaPlay))
        self.btn_stop = QtWidgets.QPushButton("Stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.setIcon(self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_MediaStop))
        btn_row.addWidget(self.btn_start)
        btn_row.addWidget(self.btn_stop)
        left_layout.addLayout(btn_row)
        self.progress = QtWidgets.QProgressBar()
        self.progress.setMinimum(0)
        self.progress.setMaximum(1)
        self.progress.setValue(0)
        left_layout.addWidget(self.progress)
        self.lbl_status = QtWidgets.QLabel("Idle")
        left_layout.addWidget(self.lbl_status)
        left_layout.addStretch(1)
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_stop.clicked.connect(self.stop_scan)
        btn_browse_ua.clicked.connect(self._load_user_agents_from_file)
        splitter.addWidget(left)
        splitter.setStretchFactor(0, 0)

    def _build_right_panel(self, splitter: QtWidgets.QSplitter):
        right = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(right)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.tabs = QtWidgets.QTabWidget()
        layout.addWidget(self.tabs)
        tab_results = QtWidgets.QWidget()
        res_layout = QtWidgets.QVBoxLayout(tab_results)
        res_layout.setContentsMargins(8, 8, 8, 8)
        res_layout.setSpacing(4)
        filter_row = QtWidgets.QHBoxLayout()
        filter_row.addWidget(QtWidgets.QLabel("Filter:"))
        self.filter_text = QtWidgets.QLineEdit()
        self.filter_text.setPlaceholderText("Type to filter results…")
        filter_row.addWidget(self.filter_text)
        self.filter_severity = QtWidgets.QComboBox()
        self.filter_severity.addItem("All severities")
        self.filter_severity.addItems(["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        filter_row.addWidget(self.filter_severity)
        res_layout.addLayout(filter_row)
        self.model = ResultTableModel()
        self.proxy_model = ResultFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        self.table = QtWidgets.QTableView()
        self.table.setModel(self.proxy_model)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QtWidgets.QTableView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QTableView.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        res_layout.addWidget(self.table)
        self.tabs.addTab(tab_results, "Results")
        tab_logs = QtWidgets.QWidget()
        logs_layout = QtWidgets.QVBoxLayout(tab_logs)
        logs_layout.setContentsMargins(8, 8, 8, 8)
        logs_layout.setSpacing(4)
        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        logs_layout.addWidget(self.log_view)
        self.tabs.addTab(tab_logs, "Logs")
        self.filter_text.textChanged.connect(self._on_filter_changed)
        self.filter_severity.currentIndexChanged.connect(self._on_filter_changed)
        self.table.doubleClicked.connect(self._on_row_double_clicked)
        splitter.addWidget(right)
        splitter.setStretchFactor(1, 1)

    def _build_status_bar(self):
        self.status = self.statusBar()
        self.status.showMessage("Ready")

    def _build_menu(self):
        bar = self.menuBar()
        file_menu = bar.addMenu("&File")
        act_quit = QtGui.QAction("Quit", self)
        act_quit.setShortcut(QtGui.QKeySequence.Quit)
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)
        view_menu = bar.addMenu("&View")
        self.act_toggle_theme = QtGui.QAction("Toggle dark/light theme", self)
        self.act_toggle_theme.setCheckable(True)
        self.act_toggle_theme.setChecked(True)
        self.act_toggle_theme.triggered.connect(self._toggle_theme)
        view_menu.addAction(self.act_toggle_theme)
        help_menu = bar.addMenu("&Help")
        act_about = QtGui.QAction("About Yumi GUI", self)
        act_about.triggered.connect(self._show_about_dialog)
        help_menu.addAction(act_about)

    def _apply_dark_theme(self):
        app = QtWidgets.QApplication.instance()
        if not app:
            return
        app.setStyle("Fusion")
        palette = QtGui.QPalette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor(30, 30, 30))
        palette.setColor(QtGui.QPalette.WindowText, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.Base, QtGui.QColor(25, 25, 25))
        palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(40, 40, 40))
        palette.setColor(QtGui.QPalette.ToolTipBase, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.ToolTipText, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.Text, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.Button, QtGui.QColor(45, 45, 45))
        palette.setColor(QtGui.QPalette.ButtonText, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.BrightText, QtCore.Qt.red)
        palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(64, 128, 255))
        palette.setColor(QtGui.QPalette.HighlightedText, QtCore.Qt.black)
        app.setPalette(palette)

    def _apply_light_theme(self):
        app = QtWidgets.QApplication.instance()
        if app:
            app.setStyle("Fusion")
            app.setPalette(app.style().standardPalette())

    def start_scan(self):
        target = self.input_target.text().strip()
        if not target:
            QtWidgets.QMessageBox.warning(self, "Input required", "Please enter a target to scan.")
            return
        output_file = self.output_path.text().strip() or "gui_report.json"
        threads = int(self.spin_threads.value())
        if self._thread is not None:
            QtWidgets.QMessageBox.information(self, "Scan running", "A scan is already running. Please stop it first.")
            return
        user_agent = None
        if self.chk_use_ua.isChecked() and self._user_agents:
            user_agent = random.choice(self._user_agents)
            self._current_user_agent = user_agent
            self.lbl_current_ua.setText(f"Current User-Agent: {user_agent}")
        else:
            self._current_user_agent = None
            self.lbl_current_ua.setText("Current User-Agent: default")
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.lbl_status.setText("Running scan…")
        self.status.showMessage(f"Scanning {target}")
        self.log_view.appendPlainText(f"[{utc_now()}] Starting scan: {target}")
        if user_agent:
            self.log_view.appendPlainText(f"[{utc_now()}] Using User-Agent: {user_agent}")
        self.progress.setRange(0, 0)
        self.model.set_results([])
        out_abs = os.path.abspath(output_file)
        self._thread = QtCore.QThread(self)
        self._worker = ScanWorker(target, out_abs, threads, user_agent)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_scan_finished)
        self._worker.log.connect(self._on_scan_log)
        self._worker.results_ready.connect(self._on_results_ready)
        self._worker.finished.connect(self._thread.quit)
        self._thread.finished.connect(self._cleanup_thread)
        self._thread.start()

    def stop_scan(self):
        if self._worker:
            self._worker.request_cancel()
            self.lbl_status.setText("Cancellation requested…")
            self.log_view.appendPlainText(f"[{utc_now()}] Cancel requested")
            self.btn_stop.setEnabled(False)

    @QtCore.Slot(bool, str)
    def _on_scan_finished(self, success: bool, error_message: str):
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        if success:
            self.lbl_status.setText("Scan finished")
            self.status.showMessage("Scan finished", 5000)
        else:
            self.lbl_status.setText("Scan failed")
            self.status.showMessage("Scan failed", 5000)
            if error_message:
                QtWidgets.QMessageBox.critical(self, "Scan failed", error_message)
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.log_view.appendPlainText(f"[{utc_now()}] Scan finished (success={success})")

    @QtCore.Slot(str)
    def _on_scan_log(self, message: str):
        self.log_view.appendPlainText(f"[{utc_now()}] {message}")

    @QtCore.Slot(list)
    def _on_results_ready(self, results: List[ResultItem]):
        self.model.set_results(results)
        self.tabs.setCurrentIndex(0)

    def _cleanup_thread(self):
        self._thread = None
        self._worker = None

    def _on_filter_changed(self):
        text = self.filter_text.text()
        self.proxy_model.set_filter_text(text)
        severity_index = self.filter_severity.currentIndex()
        severity_filter = None
        if severity_index > 0:
            severity_filter = self.filter_severity.currentText()
        self.proxy_model.set_severity_filter(severity_filter)

    def _on_row_double_clicked(self, index: QtCore.QModelIndex):
        src_idx = self.proxy_model.mapToSource(index)
        row = src_idx.row()
        item = self.model.result_at(row)
        if not item:
            return
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Finding details")
        dlg.resize(650, 400)
        layout = QtWidgets.QFormLayout(dlg)
        layout.addRow("File:", QtWidgets.QLabel(item.file))
        layout.addRow("Endpoint:", QtWidgets.QLabel(item.endpoint))
        layout.addRow("Severity:", QtWidgets.QLabel(item.severity))
        layout.addRow("Line:", QtWidgets.QLabel(str(item.line)))
        layout.addRow("Secret:", QtWidgets.QLabel(item.secret))
        snippet_edit = QtWidgets.QPlainTextEdit()
        snippet_edit.setPlainText(item.snippet)
        snippet_edit.setReadOnly(True)
        layout.addRow("Snippet:", snippet_edit)
        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(dlg.accept)
        layout.addRow(btn_close)
        dlg.exec()

    def _toggle_theme(self, checked: bool):
        if checked:
            self._apply_dark_theme()
        else:
            self._apply_light_theme()

    def _show_about_dialog(self):
        QtWidgets.QMessageBox.information(
            self,
            "About Yumi GUI",
            "Yumi : GUI\n\nDesktop interface for the Yumi scanning engine.\nBuilt with PySide6.",
        )

    def _load_user_agents_from_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select User-Agent file",
            "",
            "Text files (*.txt);;All files (*)",
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f.readlines()]
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to read file: {e}")
            return
        user_agents = [line for line in lines if line and not line.startswith("#")]
        if not user_agents:
            QtWidgets.QMessageBox.warning(self, "No User-Agents", "The selected file does not contain any valid user-agent strings.")
            return
        self._user_agents = user_agents
        self.ua_file_path.setText(path)
        self.chk_use_ua.setEnabled(True)
        example = random.choice(self._user_agents)
        self.lbl_current_ua.setText(f"Current User-Agent: {example} (example; actual will be random per scan)")

    def closeEvent(self, event: QtGui.QCloseEvent):
        if self._thread and self._thread.isRunning():
            reply = QtWidgets.QMessageBox.question(
                self,
                "Quit",
                "A scan is currently running. Do you really want to quit?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            )
            if reply != QtWidgets.QMessageBox.Yes:
                event.ignore()
                return
        super().closeEvent(event)


def main():
    app = QtWidgets.QApplication(sys.argv)
    signal.signal(signal.SIGINT, handle_sigint)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

