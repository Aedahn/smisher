"""SQLite persistence for emails and analysis results."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FOLDER_INBOX = "inbox"
FOLDER_PHISHING = "phishing"


@dataclass
class Email:
    id: int
    email_index: int
    label: int | None
    body: str
    metadata: str
    folder: str
    trusted: bool
    analyzed_at: str | None
    text_verdict: str | None
    text_confidence: float | None
    text_reason: str | None
    url_verdict: str | None
    url_confidence: float | None
    url_reason: str | None
    meta_verdict: str | None
    meta_confidence: float | None
    meta_reason: str | None
    final_verdict: str | None
    phishing_score: float | None
    explanation: str | None
    model: str | None
    analysis_time_seconds: float | None

    @property
    def subject(self) -> str:
        for line in self.metadata.splitlines():
            lower = line.lower().strip()
            if lower.startswith("subject:"):
                return line.split(":", 1)[1].strip()
        for line in self.body.splitlines():
            lower = line.lower().strip()
            if lower.startswith("subject:"):
                return line.split(":", 1)[1].strip()
        return f"Email #{self.email_index}"

    @property
    def is_analyzed(self) -> bool:
        return self.final_verdict is not None

    @property
    def predicted_label(self) -> int | None:
        if self.final_verdict is None:
            return None
        if self.final_verdict.lower() == "phishing":
            return 1
        if self.final_verdict.lower() == "legitimate":
            return 0
        return None

    @property
    def prediction_correct(self) -> bool | None:
        if self.label is None or self.predicted_label is None:
            return None
        return self.label == self.predicted_label


class Database:
    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_index INTEGER NOT NULL,
                label INTEGER,
                body TEXT NOT NULL,
                metadata TEXT NOT NULL DEFAULT '',
                folder TEXT NOT NULL DEFAULT 'inbox',
                trusted INTEGER NOT NULL DEFAULT 0,
                analyzed_at TEXT,
                text_verdict TEXT,
                text_confidence REAL,
                text_reason TEXT,
                url_verdict TEXT,
                url_confidence REAL,
                url_reason TEXT,
                meta_verdict TEXT,
                meta_confidence REAL,
                meta_reason TEXT,
                final_verdict TEXT,
                phishing_score REAL,
                explanation TEXT,
                model TEXT,
                analysis_time_seconds REAL,
                created_at TEXT NOT NULL,
                UNIQUE(email_index)
            );

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def _row_to_email(self, row: sqlite3.Row) -> Email:
        return Email(
            id=row["id"],
            email_index=row["email_index"],
            label=row["label"],
            body=row["body"],
            metadata=row["metadata"] or "",
            folder=row["folder"],
            trusted=bool(row["trusted"]),
            analyzed_at=row["analyzed_at"],
            text_verdict=row["text_verdict"],
            text_confidence=row["text_confidence"],
            text_reason=row["text_reason"],
            url_verdict=row["url_verdict"],
            url_confidence=row["url_confidence"],
            url_reason=row["url_reason"],
            meta_verdict=row["meta_verdict"],
            meta_confidence=row["meta_confidence"],
            meta_reason=row["meta_reason"],
            final_verdict=row["final_verdict"],
            phishing_score=row["phishing_score"],
            explanation=row["explanation"],
            model=row["model"],
            analysis_time_seconds=row["analysis_time_seconds"],
        )

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM app_settings WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self._conn.commit()

    def email_exists(self, email_index: int) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM emails WHERE email_index = ?", (email_index,)
        ).fetchone()
        return row is not None

    def insert_email(
        self,
        email_index: int,
        body: str,
        metadata: str,
        label: int | None = None,
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        cur = self._conn.execute(
            """
            INSERT INTO emails (email_index, label, body, metadata, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (email_index, label, body, metadata, now),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def get_emails(self, folder: str | None = None) -> list[Email]:
        if folder:
            rows = self._conn.execute(
                "SELECT * FROM emails WHERE folder = ? ORDER BY email_index",
                (folder,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM emails ORDER BY email_index"
            ).fetchall()
        return [self._row_to_email(r) for r in rows]

    def remove_email(self, email_id: int) -> None:
        self._conn.execute("DELETE FROM emails WHERE id = ?", (email_id,))
        self._conn.commit()

    def clear_all_emails(self) -> None:
        self._conn.execute("DELETE FROM emails")
        self._conn.commit()

    def get_email(self, email_id: int) -> Email | None:
        row = self._conn.execute(
            "SELECT * FROM emails WHERE id = ?", (email_id,)
        ).fetchone()
        return self._row_to_email(row) if row else None

    def get_unanalyzed_emails(self, folder: str | None = None) -> list[Email]:
        query = "SELECT * FROM emails WHERE final_verdict IS NULL"
        params: tuple[Any, ...] = ()
        if folder:
            query += " AND folder = ?"
            params = (folder,)
        query += " ORDER BY email_index"
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_email(r) for r in rows]

    def move_email(self, email_id: int, folder: str) -> None:
        self._conn.execute(
            "UPDATE emails SET folder = ? WHERE id = ?",
            (folder, email_id),
        )
        self._conn.commit()

    def set_trusted(self, email_id: int, trusted: bool) -> None:
        self._conn.execute(
            "UPDATE emails SET trusted = ? WHERE id = ?",
            (1 if trusted else 0, email_id),
        )
        self._conn.commit()

    def save_analysis(
        self,
        email_id: int,
        result: dict[str, Any],
        analysis_time: float,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """
            UPDATE emails SET
                analyzed_at = ?,
                text_verdict = ?,
                text_confidence = ?,
                text_reason = ?,
                url_verdict = ?,
                url_confidence = ?,
                url_reason = ?,
                meta_verdict = ?,
                meta_confidence = ?,
                meta_reason = ?,
                final_verdict = ?,
                phishing_score = ?,
                explanation = ?,
                model = ?,
                analysis_time_seconds = ?
            WHERE id = ?
            """,
            (
                now,
                result.get("text_verdict"),
                result.get("text_confidence"),
                result.get("text_reason"),
                result.get("url_verdict"),
                result.get("url_confidence"),
                result.get("url_reason"),
                result.get("meta_verdict"),
                result.get("meta_confidence"),
                result.get("meta_reason"),
                result.get("final_verdict"),
                result.get("phishing_score"),
                result.get("explanation"),
                result.get("model"),
                analysis_time,
                email_id,
            ),
        )
        self._conn.commit()

    def get_statistics(self) -> dict[str, Any]:
        total = self._conn.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
        analyzed = self._conn.execute(
            "SELECT COUNT(*) FROM emails WHERE final_verdict IS NOT NULL"
        ).fetchone()[0]
        legit = self._conn.execute(
            "SELECT COUNT(*) FROM emails WHERE final_verdict = 'Legitimate'"
        ).fetchone()[0]
        phishing = self._conn.execute(
            "SELECT COUNT(*) FROM emails WHERE final_verdict = 'Phishing'"
        ).fetchone()[0]
        avg_time_row = self._conn.execute(
            "SELECT AVG(analysis_time_seconds) FROM emails "
            "WHERE analysis_time_seconds IS NOT NULL"
        ).fetchone()[0]

        correct = 0
        incorrect = 0
        labeled_analyzed = self._conn.execute(
            """
            SELECT label, final_verdict FROM emails
            WHERE label IS NOT NULL AND final_verdict IS NOT NULL
            """
        ).fetchall()
        for row in labeled_analyzed:
            predicted = 1 if row["final_verdict"] == "Phishing" else 0
            if row["label"] == predicted:
                correct += 1
            else:
                incorrect += 1

        return {
            "total": total,
            "analyzed": analyzed,
            "legitimate_predictions": legit,
            "phishing_predictions": phishing,
            "correct": correct,
            "incorrect": incorrect,
            "avg_analysis_time": avg_time_row or 0.0,
            "inbox_count": self._conn.execute(
                "SELECT COUNT(*) FROM emails WHERE folder = ?", (FOLDER_INBOX,)
            ).fetchone()[0],
            "phishing_folder_count": self._conn.execute(
                "SELECT COUNT(*) FROM emails WHERE folder = ?", (FOLDER_PHISHING,)
            ).fetchone()[0],
        }

    def clear_all_emails(self) -> None:
        self._conn.execute("DELETE FROM emails")
        self._conn.commit()
