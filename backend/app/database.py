import aiosqlite
import json
from datetime import datetime

DB_PATH = "phishguard.db"


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at  TEXT NOT NULL,
                url         TEXT NOT NULL,
                subject     TEXT,
                sender      TEXT,
                body_text   TEXT,
                links       TEXT,   -- JSON array
                analysis    TEXT,   -- JSON object
                reporter_email TEXT,
                status      TEXT NOT NULL DEFAULT 'pending',  -- pending | reviewed | resolved
                admin_notes TEXT,
                feedback_sent_at TEXT
            )
        """)
        await db.commit()


async def save_report(data: dict) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            INSERT INTO reports
                (created_at, url, subject, sender, body_text, links, analysis, reporter_email, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        """, (
            datetime.utcnow().isoformat(),
            data.get("url", ""),
            data.get("subject"),
            data.get("sender"),
            data.get("body_text"),
            json.dumps(data.get("links") or []),
            json.dumps(data.get("analysis") or {}),
            data.get("reporter_email"),
        ))
        await db.commit()
        return cursor.lastrowid


async def get_reports(status: str = None) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if status:
            cursor = await db.execute(
                "SELECT * FROM reports WHERE status = ? ORDER BY created_at DESC", (status,)
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM reports ORDER BY created_at DESC"
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_report(report_id: int) -> dict | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def update_report(report_id: int, status: str, admin_notes: str = None):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE reports SET status = ?, admin_notes = ? WHERE id = ?",
            (status, admin_notes, report_id)
        )
        await db.commit()


async def mark_feedback_sent(report_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE reports SET feedback_sent_at = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), report_id)
        )
        await db.commit()
