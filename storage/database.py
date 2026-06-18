import sqlite3
import json
from datetime import datetime
from pathlib import Path


class IncidentDatabase:
    """
    Stores all analyzed incidents in SQLite.
    This gives the project memory — the agent can look up
    past incidents to spot patterns.
    """

    def __init__(self, db_path="./storage/incidents.db"):
        Path("./storage").mkdir(exist_ok=True)
        self.db_path = db_path
        self._create_tables()

    def _create_tables(self):
        """Create database tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    event_type TEXT,
                    severity_label TEXT,
                    severity_score INTEGER,
                    source_ip TEXT,
                    destination_ip TEXT,
                    hostname TEXT,
                    mitre_tactic TEXT,
                    mitre_technique TEXT,
                    vt_malicious_votes INTEGER,
                    abuse_confidence_score INTEGER,
                    ai_verdict TEXT,
                    ai_analysis TEXT,
                    timestamp TEXT,
                    created_at TEXT
                )
            """)
            conn.commit()
        print("[DB] Database initialized")

    def save_incident(self, analysis_result: dict):
        """Save a complete incident to the database."""
        alert = analysis_result["alert"]
        intel = analysis_result["threat_intel"]
        ai_analysis = analysis_result["ai_analysis"]

        # Extract verdict from AI analysis
        verdict = "NEEDS INVESTIGATION"
        if "TRUE POSITIVE" in ai_analysis.upper():
            verdict = "TRUE POSITIVE"
        elif "FALSE POSITIVE" in ai_analysis.upper():
            verdict = "FALSE POSITIVE"

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO incidents 
                (alert_id, event_type, severity_label, severity_score,
                 source_ip, destination_ip, hostname, mitre_tactic,
                 mitre_technique, vt_malicious_votes, abuse_confidence_score,
                 ai_verdict, ai_analysis, timestamp, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                alert["alert_id"],
                alert["event_type"],
                alert["severity_label"],
                alert["severity_score"],
                alert["source_ip"],
                alert["destination_ip"],
                alert["hostname"],
                alert.get("mitre_tactic", "Unknown"),
                alert.get("mitre_technique", "Unknown"),
                intel["virustotal"].get("malicious_votes", 0),
                intel["abuseipdb"].get("abuse_confidence_score", 0),
                verdict,
                ai_analysis,
                alert["timestamp"],
                datetime.now().isoformat()
            ))
            conn.commit()

        print(f"[DB] Saved incident: {alert['alert_id']}")

    def get_all_incidents(self) -> list:
        """Retrieve all incidents for the dashboard."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC"
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_recent_incidents(self, limit=10) -> list:
        """Get most recent incidents."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?",
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]