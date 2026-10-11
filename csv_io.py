"""CSV import and export utilities."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from database import Database, Email


REQUIRED_COLUMNS = {"email_index", "body", "metadata"}
OPTIONAL_COLUMNS = {"label"}


@dataclass
class ImportResult:
    imported: int
    skipped: int
    errors: list[str]


def validate_csv_columns(fieldnames: list[str] | None) -> list[str]:
    if not fieldnames:
        return ["CSV file has no header row."]
    missing = REQUIRED_COLUMNS - set(fieldnames)
    if missing:
        return [f"Missing required column(s): {', '.join(sorted(missing))}"]
    return []


def import_csv(db: Database, path: Path) -> ImportResult:
    imported = 0
    skipped = 0
    errors: list[str] = []

    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        col_errors = validate_csv_columns(reader.fieldnames)
        if col_errors:
            return ImportResult(0, 0, col_errors)

        for row_num, row in enumerate(reader, start=2):
            try:
                email_index = int(row["email_index"].strip())
            except (KeyError, ValueError, AttributeError):
                errors.append(f"Row {row_num}: invalid email_index")
                continue

            body = row.get("body", "")
            metadata = row.get("metadata", "")
            if body is None:
                body = ""
            if metadata is None:
                metadata = ""

            label = None
            if "label" in row and row["label"] not in (None, ""):
                try:
                    label = int(str(row["label"]).strip())
                except ValueError:
                    errors.append(f"Row {row_num}: invalid label")
                    continue

            if db.email_exists(email_index):
                skipped += 1
                continue

            db.insert_email(email_index, body, metadata, label)
            imported += 1

    return ImportResult(imported, skipped, errors)


EXPORT_COLUMNS = [
    "email_index",
    "true_label",
    "predicted_label",
    "phishing_score",
    "analysis_time_seconds",
    "text_verdict",
    "text_confidence",
    "text_reason",
    "url_verdict",
    "url_confidence",
    "url_reason",
    "meta_verdict",
    "meta_confidence",
    "meta_reason",
    "explanation",
    "model",
]


def export_results(db: Database, path: Path) -> int:
    emails = db.get_emails()
    analyzed = [e for e in emails if e.is_analyzed]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=EXPORT_COLUMNS)
        writer.writeheader()
        for email in analyzed:
            writer.writerow(
                {
                    "email_index": email.email_index,
                    "true_label": email.label if email.label is not None else "",
                    "predicted_label": email.predicted_label
                    if email.predicted_label is not None
                    else "",
                    "phishing_score": email.phishing_score or "",
                    "analysis_time_seconds": email.analysis_time_seconds or "",
                    "text_verdict": email.text_verdict or "",
                    "text_confidence": email.text_confidence or "",
                    "text_reason": email.text_reason or "",
                    "url_verdict": email.url_verdict or "",
                    "url_confidence": email.url_confidence or "",
                    "url_reason": email.url_reason or "",
                    "meta_verdict": email.meta_verdict or "",
                    "meta_confidence": email.meta_confidence or "",
                    "meta_reason": email.meta_reason or "",
                    "explanation": email.explanation or "",
                    "model": email.model or "",
                }
            )
    return len(analyzed)
