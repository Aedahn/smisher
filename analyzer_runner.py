"""QProcess-based analyzer — avoids macOS fork crashes from QThread+subprocess."""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, Signal

from database import Email


def get_analyzer_path() -> Path:
    return Path(__file__).resolve().parent / "analyzer.py"


@dataclass
class _PendingJob:
    email_id: int
    body: str
    metadata: str
    model: str


class AnalyzerRunner(QObject):
    """Runs analyzer.py in a persistent QProcess (loads the model once)."""

    single_finished = Signal(int, dict, float)
    single_error = Signal(int, str)
    batch_progress = Signal(int, int, int)
    batch_finished = Signal()
    batch_cancelled = Signal()
    status_message = Signal(str)
    busy_changed = Signal(bool)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._process: QProcess | None = None
        self._ready = False
        self._starting = False
        self._current: _PendingJob | None = None
        self._queue: list[_PendingJob] = []
        self._stdout_buffer = ""
        self._batch_total = 0
        self._batch_done = 0
        self._batch_active = False
        self._cancelled = False
        self._start_time = 0.0
        self._selected_model = "gemma2_9b"
        self._active_model = None

    def is_busy(self) -> bool:
        return self._current is not None or self._starting or bool(self._queue)

    @property
    def current_email_id(self) -> int | None:
        return self._current.email_id if self._current else None

    def is_email_in_progress(self, email_id: int) -> bool:
        return bool((self._current and self._current.email_id == email_id) or
                    any(job.email_id == email_id for job in self._queue))

    @property
    def is_batch_active(self) -> bool:
        return self._batch_active

    def get_email_analysis_state(self, email_id: int) -> str | None:
        if self._current and self._current.email_id == email_id:
            return "analyzing"
        if any(job.email_id == email_id for job in self._queue):
            return "queued"
        return None

    def set_model(self, model: str) -> None:
        normalized = "gemma2_9b"
        if normalized == self._selected_model:
            return

        self._selected_model = normalized
        self._cancelled = False
        self._batch_active = False
        self._batch_total = 0
        self._batch_done = 0
        self._queue.clear()
        self._current = None
        self._kill_process()
        self._emit_busy(False)
        self.status_message.emit(f"Model switched to {normalized}")

    def analyze_single(self, email_id: int, body: str, metadata: str, model: str | None = None) -> bool:
        model_name = (model or self._selected_model).strip().lower()
        
        # Check if already current or queued
        if self._current and self._current.email_id == email_id:
            return True
        if any(job.email_id == email_id for job in self._queue):
            return True

        new_job = _PendingJob(email_id, body, metadata, model_name)
        was_idle = self._current is None and not self._queue
        self._queue.append(new_job)
        self._cancelled = False

        if was_idle:
            self._batch_active = False
            self._batch_total = 1
            self._batch_done = 0

        if self._current is None:
            self._start_next_queued_job()

        return True

    def _start_next_queued_job(self) -> None:
        if not self._queue:
            self._current = None
            self._emit_busy(False)
            return

        self._current = self._queue.pop(0)
        self._emit_busy(True)
        self._ensure_process()

    def analyze_batch(self, emails: list[Email], model: str | None = None) -> bool:
        if self.is_busy():
            return False
        if not emails:
            return False

        model_name = (model or self._selected_model).strip().lower()
        self._batch_active = True
        self._batch_total = len(emails)
        self._batch_done = 0
        self._cancelled = False
        self._queue.clear()

        for email in emails:
            self._queue.append(
                _PendingJob(email.id, email.body, email.metadata, model_name)
            )

        self.status_message.emit(f"Batch analysis: 0 / {self._batch_total}")
        self._start_next_queued_job()
        return True

    def cancel_batch(self) -> None:
        self.cancel_current()

    def cancel_current(self) -> None:
        self._cancelled = True
        self._queue.clear()
        email_id = self.current_email_id
        self._kill_process()
        self._current = None
        self._finish_batch(cancelled=True)
        if email_id is not None:
            self.status_message.emit("Cancelled analysis queue")

    def _emit_busy(self, busy: bool) -> None:
        self.busy_changed.emit(busy)

    def _ensure_process(self) -> None:
        if self._process and self._process.state() != QProcess.ProcessState.NotRunning:
            if self._ready:
                self._send_next()
            return

        self._starting = True
        self._ready = False
        self.status_message.emit("Starting analyzer…")

        self._process = QProcess(self)
        model_arg = self._selected_model or "gemma2_9b"
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
        self._process.readyReadStandardOutput.connect(self._on_stdout)
        self._process.readyReadStandardError.connect(self._on_stderr)
        self._process.finished.connect(self._on_process_finished)
        self._process.errorOccurred.connect(self._on_process_error)

        analyzer_path = get_analyzer_path()
        if not analyzer_path.exists():
            self._fail_current(f"analyzer.py not found at {analyzer_path}")
            return

        self._process.start(sys.executable, [str(analyzer_path), "--serve", "--model", model_arg])

    def _on_stderr(self) -> None:
        if not self._process:
            return
        text = self._process.readAllStandardError().data().decode("utf-8", errors="replace")
        if "READY" in text:
            self._ready = True
            self._starting = False
            self.status_message.emit("Analyzer ready")
            self._send_next()

    def _on_stdout(self) -> None:
        if not self._process:
            return
        chunk = self._process.readAllStandardOutput().data().decode("utf-8", errors="replace")
        self._stdout_buffer += chunk
        while "\n" in self._stdout_buffer:
            line, self._stdout_buffer = self._stdout_buffer.split("\n", 1)
            line = line.strip()
            if line:
                self._handle_result_line(line)

    def _handle_result_line(self, line: str) -> None:
        if not self._current:
            return
        email_id = self._current.email_id
        elapsed = time.perf_counter() - self._start_time

        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            self._fail_current(f"Invalid JSON from analyzer: {line[:200]}")
            return

        if "error" in result:
            self._fail_current(result["error"])
            return

        self._batch_done += 1
        if self._batch_active:
            self.batch_progress.emit(self._batch_done, self._batch_total, email_id)

        self.single_finished.emit(email_id, result, elapsed)
        self._current = None

        if self._cancelled:
            self._queue.clear()
            self._finish_batch(cancelled=True)
            return

        if self._queue:
            self._start_next_queued_job()
        else:
            self._finish_batch(cancelled=False)

    def _send_next(self) -> None:
        if not self._ready or not self._process or not self._current:
            return
        if self._cancelled:
            self._finish_batch(cancelled=True)
            return
        payload = json.dumps(
            {
                "body": self._current.body,
                "metadata": self._current.metadata,
                "model": self._current.model,
            }
        )
        self._start_time = time.perf_counter()
        self._process.write((payload + "\n").encode("utf-8"))

        if self._batch_active:
            done = self._batch_done + 1
            self.batch_progress.emit(done, self._batch_total, self._current.email_id)
        self.status_message.emit(f"Analyzing email #{self._current.email_id}…")

    def _fail_current(self, message: str) -> None:
        email_id = self._current.email_id if self._current else None
        if email_id is not None:
            self.single_error.emit(email_id, message)
        self._current = None
        self._kill_process()
        
        if self._cancelled:
            self._queue.clear()
            self._finish_batch(cancelled=True)
            return

        if self._queue:
            self._start_next_queued_job()
        else:
            self._finish_batch(cancelled=False)

    def _finish_batch(self, cancelled: bool) -> None:
        was_batch = self._batch_active
        self._batch_active = False
        self._emit_busy(False)
        if cancelled and was_batch:
            self.batch_cancelled.emit()
        elif was_batch:
            self.batch_finished.emit()
        self._batch_total = 0
        self._batch_done = 0

    def _on_process_finished(self, exit_code: int, _status) -> None:
        if self._current and exit_code != 0:
            stderr = ""
            if self._process:
                stderr = self._process.readAllStandardError().data().decode(
                    "utf-8", errors="replace"
                ).strip()
            msg = stderr or f"Analyzer exited with code {exit_code}"
            self._fail_current(msg)
        self._ready = False
        self._starting = False

    def _on_process_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.FailedToStart:
            self._fail_current("Failed to start analyzer process.")

    def _kill_process(self) -> None:
        if self._process and self._process.state() != QProcess.ProcessState.NotRunning:
            self._process.kill()
            self._process.waitForFinished(3000)
        self._ready = False
        self._starting = False

    def shutdown(self) -> None:
        self._current = None
        self._kill_process()
