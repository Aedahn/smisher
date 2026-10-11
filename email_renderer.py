"""Safe plain-text email rendering with optional link activation."""

from __future__ import annotations

import html
import re
from urllib.parse import urlparse

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices

URL_PATTERN = re.compile(
    r"(https?://[^\s<>\"{}|\\^`\[\]]+|hxxps?://[^\s<>\"{}|\\^`\[\]]+)",
    re.IGNORECASE,
)


def extract_urls(text: str) -> list[str]:
    return list(dict.fromkeys(URL_PATTERN.findall(text)))


def render_plain_text(text: str, links_enabled: bool = False) -> str:
    """Return HTML-safe content for QLabel/QTextBrowser (no script/style)."""
    escaped = html.escape(text)
    if not links_enabled:
        return f'<div style="white-space: pre-wrap; font-family: inherit; margin: 0; background: transparent; border: none; padding: 0;">{escaped}</div>'

    def replace_url(match: re.Match[str]) -> str:
        url = match.group(1)
        safe_url = html.escape(url)
        return (
            f'<a href="{safe_url}">'
            f"{safe_url}</a>"
        )

    linked = URL_PATTERN.sub(replace_url, escaped)
    return (
        f'<div style="white-space: pre-wrap; font-family: inherit; margin: 0; background: transparent; border: none; padding: 0;">{linked}</div>'
    )


def open_external_url(url: QUrl) -> bool:
    scheme = url.scheme().lower()
    if scheme not in ("http", "https"):
        return False
    QDesktopServices.openUrl(url)
    return True
