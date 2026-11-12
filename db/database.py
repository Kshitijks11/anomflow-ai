import os
import sys
import sqlite3
from contextlib import closing
from datetime import datetime
import pandas as pd

# folder of the .exe when packaged, project folder when run as a script
if getattr(sys, "frozen", False):
    BASE = os.path.dirname(sys.executable)
else:
    BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DB_PATH = os.path.join(BASE, "db", "anomflow.db")


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS flow_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT, src_port INTEGER,
                dst_ip TEXT, dst_port INTEGER,
                protocol TEXT,
                duration REAL, packet_count INTEGER, total_bytes INTEGER,
                byte_rate REAL, packet_rate REAL,
                label TEXT NOT NULL,
                confidence REAL NOT NULL
            )
        """)


def save_flows(df):
    init_db()
    now = datetime.now().isoformat(timespec="seconds")
    rows = [
        (now, r.src_ip, int(r.src_port), r.dst_ip, int(r.dst_port), r.protocol,
         float(r.duration), int(r.packet_count), int(r.total_bytes),
         float(r.byte_rate), float(r.packet_rate),
         "ANOMALOUS" if r.prediction == 1 else "BENIGN", float(r.attack_prob))
        for r in df.itertuples()
    ]
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.executemany(
            "INSERT INTO flow_results (timestamp, src_ip, src_port, dst_ip, dst_port, "
            "protocol, duration, packet_count, total_bytes, byte_rate, packet_rate, "
            "label, confidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    return len(rows)


def load_recent(limit=200):
    init_db()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        return pd.read_sql(
            "SELECT * FROM flow_results ORDER BY id DESC LIMIT ?",
            conn, params=(limit,),
        )


def get_counts():
    init_db()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        total, anomalous = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(label = 'ANOMALOUS'), 0) FROM flow_results"
        ).fetchone()
    return total, int(anomalous)