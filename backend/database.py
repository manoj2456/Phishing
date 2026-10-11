"""
PhishGuard - SQLite Database Module
College CSE Mini Project: Phishing Website Detection System

Manages scan history persistence using SQLite.
Stores only URLs, risk scores, classifications, confidence scores, and timestamps.
Does not store any sensitive user credentials, OTPs, or tokens.
"""

import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "phishguard.db")


def get_connection():
    """Returns a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the scan_history table if it does not already exist."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                confidence REAL NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)
        conn.commit()


def add_scan_record(url: str, risk_score: int, classification: str, confidence: float) -> int:
    """Inserts a new scan result record into the scan_history table."""
    init_db()
    scanned_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history (url, risk_score, classification, confidence, scanned_at)
            VALUES (?, ?, ?, ?, ?)
        """, (url, risk_score, classification, round(confidence, 4), scanned_at))
        conn.commit()
        return cursor.lastrowid


def get_scan_history(limit: int = 50) -> list[dict]:
    """Retrieves recent scan history entries ordered by date descending."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, url, risk_score, classification, confidence, scanned_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        return [
            {
                "id": row["id"],
                "url": row["url"],
                "risk_score": row["risk_score"],
                "classification": row["classification"],
                "confidence": row["confidence"],
                "scanned_at": row["scanned_at"]
            }
            for row in rows
        ]


def clear_history() -> int:
    """Deletes all records from the scan_history table."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_history")
        deleted_count = cursor.rowcount
        conn.commit()
        return deleted_count


if __name__ == "__main__":
    init_db()
    print("SQLite database initialized successfully at:", DB_PATH)
