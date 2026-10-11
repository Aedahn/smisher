"""Subprocess communication with analyzer.py."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


class AnalyzerError(Exception):
    pass


def get_analyzer_path() -> Path:
    return Path(__file__).resolve().parent / "analyzer.py"


def analyze_email(body: str, metadata: str, timeout: int = 600) -> dict[str, Any]:
    """Run analyzer.py with JSON on stdin, return parsed JSON result."""
    analyzer_path = get_analyzer_path()
    if not analyzer_path.exists():
        raise AnalyzerError(f"analyzer.py not found at {analyzer_path}")

    payload = json.dumps({"body": body, "metadata": metadata})
    python = sys.executable

    try:
        proc = subprocess.run(
            [python, str(analyzer_path)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise AnalyzerError("Analysis timed out.") from exc
    except Exception as exc:
        raise AnalyzerError(f"Failed to launch analyzer: {exc}") from exc

    if proc.returncode != 0 and not proc.stdout.strip():
        stderr = proc.stderr.strip() or "Unknown analyzer error"
        raise AnalyzerError(stderr)

    stdout = proc.stdout.strip()
    if not stdout:
        raise AnalyzerError("Analyzer returned empty output.")

    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise AnalyzerError(f"Invalid JSON from analyzer: {stdout[:200]}") from exc

    if "error" in result:
        raise AnalyzerError(result["error"])

    return result
