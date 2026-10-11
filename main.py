#!/usr/bin/env python3
"""Multi LLMs — Desktop demo for multi-agent phishing detection."""

import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from database import Database
from main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Multi LLMs")
    app.setOrganizationName("MultiLLMs")
    app.setStyle("Fusion")

    db_path = Path(__file__).resolve().parent / "data" / "multillms.db"
    db = Database(db_path)

    window = MainWindow(db)
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
