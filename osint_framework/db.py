import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "osint.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target      TEXT NOT NULL,
                target_type TEXT NOT NULL,
                status      TEXT DEFAULT 'running',
                created_at  TEXT DEFAULT (datetime('now')),
                finished_at TEXT
            );

            CREATE TABLE IF NOT EXISTS results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL,
                module      TEXT NOT NULL,
                data_type   TEXT NOT NULL,
                value       TEXT NOT NULL,
                source      TEXT,
                raw         TEXT,
                created_at  TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
        """)

def create_scan(target, target_type):
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, target_type, status) VALUES (?, ?, 'running')",
            (target, target_type)
        )
        return cur.lastrowid

def finish_scan(scan_id, status="done"):
    with get_conn() as conn:
        conn.execute(
            "UPDATE scans SET status=?, finished_at=datetime('now') WHERE id=?",
            (status, scan_id)
        )

def save_results(scan_id, results):
    with get_conn() as conn:
        for r in results:
            conn.execute(
                "INSERT INTO results (scan_id, module, data_type, value, source, raw) VALUES (?,?,?,?,?,?)",
                (scan_id, r["module"], r["data_type"], r["value"], r.get("source",""), json.dumps(r.get("raw",{})))
            )

def get_scan(scan_id):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

def get_results(scan_id, data_type=None, module=None):
    with get_conn() as conn:
        q = "SELECT * FROM results WHERE scan_id=?"
        params = [scan_id]
        if data_type:
            q += " AND data_type=?"; params.append(data_type)
        if module:
            q += " AND module=?"; params.append(module)
        q += " ORDER BY module, data_type"
        rows = conn.execute(q, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try: d["raw"] = json.loads(d["raw"] or "{}")
            except: d["raw"] = {}
            out.append(d)
        return out

def get_all_scans():
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT s.*, COUNT(r.id) as result_count
            FROM scans s
            LEFT JOIN results r ON r.scan_id = s.id
            GROUP BY s.id
            ORDER BY s.id DESC
            LIMIT 50
        """).fetchall()
        return [dict(r) for r in rows]

def delete_scan(scan_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM results WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))

def get_result_summary(scan_id):
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT data_type, COUNT(*) as cnt
            FROM results WHERE scan_id=?
            GROUP BY data_type ORDER BY cnt DESC
        """, (scan_id,)).fetchall()
        return [dict(r) for r in rows]

def get_modules_used(scan_id):
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT module, COUNT(*) as cnt
            FROM results WHERE scan_id=?
            GROUP BY module ORDER BY module
        """, (scan_id,)).fetchall()
        return [dict(r) for r in rows]
