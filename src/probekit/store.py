from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import uuid

from .models import Finding, Report


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as connection, connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("""CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, target TEXT NOT NULL, project TEXT NOT NULL,
                created TEXT NOT NULL, state TEXT NOT NULL, report TEXT, error TEXT)""")

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def recover(self):
        with closing(self.connect()) as connection, connection:
            connection.execute("UPDATE scans SET state='failed', error='Travail interrompu au redémarrage.' "
                               "WHERE state IN ('queued', 'running')")

    def create(self, target: str, project: str) -> str:
        scan_id = uuid.uuid4().hex
        with closing(self.connect()) as connection, connection:
            connection.execute("INSERT INTO scans VALUES (?, ?, ?, ?, 'queued', NULL, NULL)",
                               (scan_id, target, project, datetime.now(timezone.utc).isoformat()))
        return scan_id

    def update(self, scan_id: str, state: str, report: Report | None = None, error: str | None = None):
        payload = json.dumps(report.to_dict(), ensure_ascii=False) if report is not None else None
        with closing(self.connect()) as connection, connection:
            connection.execute("UPDATE scans SET state=?, report=?, error=? WHERE id=?",
                               (state, payload, error, scan_id))

    def get(self, scan_id: str) -> dict | None:
        with closing(self.connect()) as connection:
            row = connection.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def recent(self, limit=100) -> list[dict]:
        with closing(self.connect()) as connection:
            rows = connection.execute("SELECT * FROM scans ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]


def decode_report(payload: str) -> Report:
    data = json.loads(payload)
    data["findings"] = [Finding(**item) for item in data["findings"]]
    return Report(**data)
