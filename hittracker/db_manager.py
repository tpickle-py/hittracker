# db_manager.py
import sqlite3
from datetime import datetime


class DatabaseManager:
    def __init__(self, db_name="firewall_policies.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS firewalls (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE,
            device_type TEXT
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY,
            firewall_id INTEGER,
            name TEXT,
            current_hit_count INTEGER,
            last_seen DATE,
            first_zero_hit DATE,
            last_zero_hit DATE,
            FOREIGN KEY (firewall_id) REFERENCES firewalls (id)
        )
        """)

        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS policy_history (
            id INTEGER PRIMARY KEY,
            policy_id INTEGER,
            hit_count INTEGER,
            date DATE,
            FOREIGN KEY (policy_id) REFERENCES policies (id)
        )
        """)

        self.conn.commit()

    def add_firewall(self, name, device_type):
        self.cursor.execute(
            "INSERT OR IGNORE INTO firewalls (name, device_type) VALUES (?, ?)",
            (name, device_type),
        )
        self.conn.commit()

    def update_policy(self, firewall_name, device_type, policy_name, hit_count, date):
        self.cursor.execute(
            "SELECT id FROM firewalls WHERE name = ? AND device_type = ?",
            (firewall_name, device_type),
        )
        firewall_id = self.cursor.fetchone()[0]

        self.cursor.execute(
            """
        SELECT id, current_hit_count, first_zero_hit, last_zero_hit 
        FROM policies 
        WHERE firewall_id = ? AND name = ?
        """,
            (firewall_id, policy_name),
        )
        policy_data = self.cursor.fetchone()

        if policy_data:
            policy_id, current_hit_count, first_zero_hit, last_zero_hit = policy_data

            if hit_count == 0:
                if current_hit_count > 0:
                    first_zero_hit = date
                last_zero_hit = date
            else:
                last_zero_hit = None
                if current_hit_count == 0:
                    first_zero_hit = None

            self.cursor.execute(
                """
            UPDATE policies 
            SET current_hit_count = ?, last_seen = ?, first_zero_hit = ?, last_zero_hit = ?
            WHERE id = ?
            """,
                (hit_count, date, first_zero_hit, last_zero_hit, policy_id),
            )
        else:
            self.cursor.execute(
                """
            INSERT INTO policies (firewall_id, name, current_hit_count, last_seen, first_zero_hit, last_zero_hit)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    firewall_id,
                    policy_name,
                    hit_count,
                    date,
                    date if hit_count == 0 else None,
                    date if hit_count == 0 else None,
                ),
            )
            policy_id = self.cursor.lastrowid

        self.cursor.execute(
            """
        INSERT INTO policy_history (policy_id, hit_count, date)
        VALUES (?, ?, ?)
        """,
            (policy_id, hit_count, date),
        )

        self.conn.commit()

    def get_unused_policies(self, days_threshold):
        today = datetime.now().date()
        self.cursor.execute(
            """
        SELECT f.name AS firewall_name, p.name AS policy_name, p.last_zero_hit, p.first_zero_hit
        FROM policies p
        JOIN firewalls f ON p.firewall_id = f.id
        WHERE p.current_hit_count = 0
        AND p.last_zero_hit IS NOT NULL
        AND julianday(?) - julianday(p.first_zero_hit) >= ?
        """,
            (today, days_threshold),
        )
        return self.cursor.fetchall()

    def close(self):
        self.conn.close()
