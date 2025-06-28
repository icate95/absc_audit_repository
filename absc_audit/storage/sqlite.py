"""
SQLite Storage Module for the ABSC Audit System.

Implements the data persistence backend using SQLite.
"""

import json
import os
import threading
import sqlite3
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple

from absc_audit.storage.models import Target, AuditCheck, AuditResult, AuditReport, ScheduledAudit, UserAccount, NetworkScan, NetworkDevice
from absc_audit.config.settings import Settings
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)

class SQLiteStorage:
    """
    SQLite based storage backend.

    This class manages data persistence using a SQLite database.
    It supports all CRUD operations for the system data models.
    """

    # Thread-local storage for thread-specific connections
    _thread_local = threading.local()

    def __init__(self, settings: Optional[Settings] = None, db_path: Optional[str] = None):
        """
        Initializes the SQLite storage backend.

        Args:
        settings: System configurations (optional)
        db_path: Database file path (optional)
        """
        self.settings = settings or Settings()
        self.db_path = db_path or self.settings.sqlite_path or "audit_data.db"

        # Ensure the directory exists
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)

        # Initialize the database
        self._initialize_db()

    def _initialize_db(self):
        """Initialize the database by creating tables if they do not exist."""
        self._connect()

        tables = {
            "targets": """
                CREATE TABLE IF NOT EXISTS targets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    hostname TEXT,
                    ip_address TEXT,
                    os_type TEXT,
                    os_version TEXT,
                    description TEXT,
                    "group" TEXT,
                    tags TEXT,
                    attributes TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """,
            "audit_checks": """
                CREATE TABLE IF NOT EXISTS audit_checks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    question TEXT,
                    possible_answers TEXT,
                    category TEXT,
                    priority INTEGER,
                    enabled INTEGER,
                    params TEXT
                )
            """,
            "audit_results": """
                CREATE TABLE IF NOT EXISTS audit_results (
                    id TEXT PRIMARY KEY,
                    check_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    timestamp TEXT,
                    processed_at TEXT,
                    status TEXT,
                    score REAL,
                    details TEXT,
                    raw_data TEXT,
                    notes TEXT,
                    FOREIGN KEY (check_id) REFERENCES audit_checks(id),
                    FOREIGN KEY (target_id) REFERENCES targets(id)
                )
            """,
            "audit_reports": """
                CREATE TABLE IF NOT EXISTS audit_reports (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    generated_at TEXT,
                    target_ids TEXT,
                    check_ids TEXT,
                    compliance_stats TEXT,
                    result_summary TEXT,
                    result_ids TEXT,
                    format TEXT
                )
            """,
            "scheduled_audits": """
                CREATE TABLE IF NOT EXISTS scheduled_audits (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    target_ids TEXT,
                    check_ids TEXT,
                    frequency TEXT,
                    day_of_week INTEGER,
                    day_of_month INTEGER,
                    hour INTEGER,
                    minute INTEGER,
                    enabled INTEGER,
                    last_run TEXT,
                    next_run TEXT,
                    notify_on_completion INTEGER,
                    notify_email TEXT,
                    params TEXT
                )
            """,
            "user_accounts": """
                CREATE TABLE IF NOT EXISTS user_accounts (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    role TEXT,
                    enabled INTEGER,
                    last_login TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    preferences TEXT
                )
            """
        }

        network_tables = {
            "network_scans": """
                    CREATE TABLE IF NOT EXISTS network_scans (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        start_time DATETIME NOT NULL,
                        end_time DATETIME,
                        network_ranges TEXT,
                        scan_parameters TEXT,
                        total_devices INTEGER DEFAULT 0,
                        total_open_ports INTEGER DEFAULT 0,
                        total_vulnerabilities INTEGER DEFAULT 0
                    )
                    """,
            "network_devices": """
                    CREATE TABLE IF NOT EXISTS network_devices (
                        id TEXT PRIMARY KEY,
                        scan_id TEXT,
                        ip TEXT,
                        mac TEXT,
                        hostname TEXT,
                        os TEXT,
                        os_version TEXT,
                        services TEXT,
                        is_alive BOOLEAN,
                        reachable_protocols TEXT,
                        potential_vulnerabilities TEXT,
                        open_ports TEXT,
                        closed_ports TEXT,
                        filtered_ports TEXT,
                        additional_info TEXT,
                        first_seen DATETIME,
                        last_seen DATETIME,
                        FOREIGN KEY(scan_id) REFERENCES network_scans(id)
                    )
                    """
        }

        # Unisci le tabelle
        tables.update(network_tables)

        cursor = self.conn.cursor()
        for table_name, table_schema in tables.items():
            logger.info(f"{table_name}")
            try:
                self.cursor.execute(table_schema)
            except sqlite3.Error as e:
                logger.error(f"Error creating table {table_name}: {str(e)}")

        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_audit_results_check_id ON audit_results(check_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_results_target_id ON audit_results(target_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_results_timestamp ON audit_results(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_targets_name ON targets(name)",
            "CREATE INDEX IF NOT EXISTS idx_targets_hostname ON targets(hostname)",
            "CREATE INDEX IF NOT EXISTS idx_targets_ip_address ON targets(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_user_accounts_username ON user_accounts(username)",
            "CREATE INDEX IF NOT EXISTS idx_network_devices_scan_id ON network_devices(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_network_devices_ip ON network_devices(ip)",
            "CREATE INDEX IF NOT EXISTS idx_network_devices_hostname ON network_devices(hostname)",
        ]

        for index in indexes:
            try:
                self.cursor.execute(index)
            except sqlite3.Error as e:
                logger.error(f"Error creating index: {str(e)}")

        self.conn.commit()
        self._disconnect()

    def _connect(self):
        """
        Establishes a database connection specific to the current thread.

        Each thread will have its own dedicated database connection.
        """
        try:
            # Check if the current thread already has a connection
            if not hasattr(self._thread_local, 'conn') or self._thread_local.conn is None:
                # Create a new connection for this thread
                self._thread_local.conn = sqlite3.connect(self.db_path)
                # Enable foreign key support
                self._thread_local.conn.execute("PRAGMA foreign_keys = ON")
                # Configure return of dict instead of tuple
                self._thread_local.conn.row_factory = sqlite3.Row
                self._thread_local.cursor = self._thread_local.conn.cursor()

            # Local references for your convenience
            self.conn = self._thread_local.conn
            self.cursor = self._thread_local.cursor

            return self.conn, self.cursor
        except sqlite3.Error as e:
            logger.error(f"Error connecting to SQLite database: {str(e)}")
            raise

    def _disconnect(self):
        """
        "Disconnect" from the database.

        We actually keep the connection open for the thread,
        but reset the local references.
        """
        self.conn = None
        self.cursor = None

    def close_all(self):
        """
        Closes all database connections.

        This method should be called when the application terminates.
        """
        try:
            if hasattr(self._thread_local, 'conn') and self._thread_local.conn:
                self._thread_local.conn.close()
                self._thread_local.conn = None
                self._thread_local.cursor = None
        except sqlite3.Error as e:
            logger.error(f"Error closing SQLite connection: {str(e)}")

    def _dict_to_json(self, data: Dict) -> str:
        """Converts a dictionary to a JSON string."""
        if not data:
            return "{}"
        return json.dumps(data, default=str)

    def _json_to_dict(self, json_str: str) -> Dict:
        """Converts a JSON string to a dictionary."""
        if not json_str or json_str == "{}":
            return {}
        return json.loads(json_str)

    def _list_to_json(self, data: List) -> str:
        """Converts a list to a JSON string."""
        if not data:
            return "[]"
        return json.dumps(data, default=str)

    def _json_to_list(self, json_str: str) -> List:
        """Converts a JSON string to a list."""
        if not json_str or json_str == "[]":
            return []
        return json.loads(json_str)

    # ----- Target Methods -----

    def save_target(self, target: Target) -> Target:
        """
        Save a target to the database.

        Args:
        target: Target to save

        Returns:
        Target saved
        """
        self._connect()

        try:
            target.updated_at = datetime.datetime.now()

            data = (
                target.id,
                target.name,
                target.hostname,
                target.ip_address,
                target.os_type,
                target.os_version,
                target.description,
                target.group,
                self._list_to_json(target.tags),
                self._dict_to_json(target.attributes),
                target.created_at.isoformat(),
                target.updated_at.isoformat()
            )

            query = """
                INSERT OR REPLACE INTO targets
                (id, name, hostname, ip_address, os_type, os_version, description, "group", tags, attributes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """

            self.cursor.execute(query, data)
            self.conn.commit()

            return target

        except sqlite3.Error as e:
            if self.conn:
                self.conn.rollback()
            logger.error(f"Error saving target {target.id}: {str(e)}")
            raise
        finally:
            # Non chiudiamo realmente la connessione, la manteniamo per il thread
            pass

    def get_target(self, target_id: str) -> Optional[Target]:
        """
        Retrieves a target from the database.

        Args:
        target_id: ID of the target to retrieve

        Returns:
        Target retrieved or None if not found
        """
        self._connect()

        try:
            query = "SELECT * FROM targets WHERE id = ?"

            self.cursor.execute(query, (target_id,))
            row = self.cursor.fetchone()

            if not row:
                return None

            target_dict = dict(row)

            target_dict["tags"] = self._json_to_list(target_dict["tags"])
            target_dict["attributes"] = self._json_to_dict(target_dict["attributes"])

            return Target.from_dict(target_dict)

        except sqlite3.Error as e:
            logger.error(f"Error retrieving target {target_id}: {str(e)}")
            raise
        finally:
            pass

    def get_all_targets(self) -> List[Target]:
        """
        Retrieve all targets from the database.

        Returns:
        List of all targets
        """
        self._connect()

        try:
            query = "SELECT * FROM targets ORDER BY name"

            self.cursor.execute(query)
            rows = self.cursor.fetchall()

            targets = []
            for row in rows:
                target_dict = dict(row)
                target_dict["tags"] = self._json_to_list(target_dict["tags"])
                target_dict["attributes"] = self._json_to_dict(target_dict["attributes"])
                targets.append(Target.from_dict(target_dict))

            return targets

        except sqlite3.Error as e:
            logger.error(f"Error retrieving all targets: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_targets_by_group(self, group: str) -> List[Target]:
        """
        Gets targets for a specific group.

        Args:
        group: Group name

        Returns:
        List of targets in the group
        """
        self._connect()

        try:
            query = "SELECT * FROM targets WHERE \"group\" = ? ORDER BY name"

            self.cursor.execute(query, (group,))
            rows = self.cursor.fetchall()

            targets = []
            for row in rows:
                target_dict = dict(row)
                target_dict["tags"] = self._json_to_list(target_dict["tags"])
                target_dict["attributes"] = self._json_to_dict(target_dict["attributes"])
                targets.append(Target.from_dict(target_dict))

            return targets

        except sqlite3.Error as e:
            logger.error(f"Error retrieving targets in group {group}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_targets_by_tag(self, tag: str) -> List[Target]:
        """
        Gets targets with a specific tag.

        Args:
        tag: Tag to search for

        Returns:
        List of targets with the tag
        """
        self._connect()

        try:
            query = "SELECT * FROM targets WHERE tags LIKE ? ORDER BY name"

            self.cursor.execute(query, (f'%"{tag}"%',))
            rows = self.cursor.fetchall()

            targets = []
            for row in rows:
                target_dict = dict(row)
                tags = self._json_to_list(target_dict["tags"])
                if tag in tags:
                    target_dict["tags"] = tags
                    target_dict["attributes"] = self._json_to_dict(target_dict["attributes"])
                    targets.append(Target.from_dict(target_dict))

            return targets

        except sqlite3.Error as e:
            logger.error(f"Error retrieving targets with tag {tag}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def delete_target(self, target_id: str) -> bool:
        """
        Delete a target from the database.

        Args:
            target_id: ID of the target to delete

        Returns:
            True if the deletion was successful, False otherwise
        """
        self._connect()

        try:
            query = "DELETE FROM targets WHERE id = ?"

            self.cursor.execute(query, (target_id,))
            self.conn.commit()

            return self.cursor.rowcount > 0

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error deleting target {target_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    # ----- Audit Check Methods -----

    def save_check(self, check: AuditCheck) -> AuditCheck:
        """
        Saves a control to the database.

        Args:
        check: Control to save

        Returns:
        Control saved
        """
        self._connect()

        try:
            data = (
                check.id,
                check.name,
                check.description,
                check.question,
                self._list_to_json(check.possible_answers),
                check.category,
                check.priority,
                int(check.enabled),
                self._dict_to_json(check.params)
            )

            query = """
                INSERT OR REPLACE INTO audit_checks
                (id, name, description, question, possible_answers, category, priority, enabled, params)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """

            self.cursor.execute(query, data)
            self.conn.commit()

            return check

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error saving check {check.id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_check(self, check_id: str) -> Optional[AuditCheck]:
        """
        Retrieves a control from the database.

        Args:
        check_id: ID of the control to retrieve

        Returns:
        Control retrieved or None if not found
        """
        self._connect()

        try:
            query = "SELECT * FROM audit_checks WHERE id = ?"

            self.cursor.execute(query, (check_id,))
            row = self.cursor.fetchone()

            if not row:
                return None

            check_dict = dict(row)

            check_dict["enabled"] = bool(check_dict["enabled"])
            check_dict["possible_answers"] = self._json_to_list(check_dict["possible_answers"])
            check_dict["params"] = self._json_to_dict(check_dict["params"])

            return AuditCheck.from_dict(check_dict)

        except sqlite3.Error as e:
            logger.error(f"Error retrieving check {check_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_all_checks(self, id) -> List[AuditCheck]:
        """
        Retrieve all controls from the database.

        Returns:
        List of all controls
        """
        self._connect()

        try:
            query = "SELECT * FROM audit_checks ORDER BY id"

            self.cursor.execute(query)
            rows = self.cursor.fetchall()

            checks = []
            for row in rows:
                check_dict = dict(row)
                check_dict["enabled"] = bool(check_dict["enabled"])
                check_dict["possible_answers"] = self._json_to_list(check_dict["possible_answers"])
                check_dict["params"] = self._json_to_dict(check_dict["params"])
                checks.append(AuditCheck.from_dict(check_dict))

            return checks

        except sqlite3.Error as e:
            logger.error(f"Error retrieving all checks: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_checks_by_category(self, category: str) -> List[AuditCheck]:
        """
        Gets controls from a specific category.

        Args:
        category: Category to search

        Returns:
        List of controls in category
        """
        self._connect()

        try:
            query = "SELECT * FROM audit_checks WHERE category = ? ORDER BY id"

            self.cursor.execute(query, (category,))
            rows = self.cursor.fetchall()

            checks = []
            for row in rows:
                check_dict = dict(row)
                check_dict["enabled"] = bool(check_dict["enabled"])
                check_dict["possible_answers"] = self._json_to_list(check_dict["possible_answers"])
                check_dict["params"] = self._json_to_dict(check_dict["params"])
                checks.append(AuditCheck.from_dict(check_dict))

            return checks

        except sqlite3.Error as e:
            logger.error(f"Error retrieving checks in category {category}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_checks_by_priority(self, priority: int) -> List[AuditCheck]:
        """
        Gets controls with a specific priority.

        Args:
        priority: Priority to search (1=high, 2=medium, 3=low)

        Returns:
        List of controls with the specified priority
        """
        self._connect()

        try:
            # Query per recuperare i controlli con la priorità specificata
            query = "SELECT * FROM audit_checks WHERE priority = ? ORDER BY id"

            # Esegui la query
            self.cursor.execute(query, (priority,))
            rows = self.cursor.fetchall()

            # Converti i risultati in oggetti AuditCheck
            checks = []
            for row in rows:
                check_dict = dict(row)
                check_dict["enabled"] = bool(check_dict["enabled"])
                check_dict["possible_answers"] = self._json_to_list(check_dict["possible_answers"])
                check_dict["params"] = self._json_to_dict(check_dict["params"])
                checks.append(AuditCheck.from_dict(check_dict))

            return checks

        except sqlite3.Error as e:
            logger.error(f"Error retrieving checks with priority {priority}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def delete_check(self, check_id: str) -> bool:
        """
        Deletes a control from the database.

        Args:
        check_id: ID of the control to delete

        Returns:
        True if the deletion was successful, False otherwise
        """
        self._connect()

        try:
            query = "DELETE FROM audit_checks WHERE id = ?"

            self.cursor.execute(query, (check_id,))
            self.conn.commit()

            return self.cursor.rowcount > 0

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error deleting check {check_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    # ----- Audit Results Methods -----

    def save_result(self, result: AuditResult) -> AuditResult:
        """
        Saves an audit result to the database.

        Args:
        result: Result to save

        Returns:
        Result saved
        """
        self._connect()

        try:
            data = (
                result.id,
                result.check_id,
                result.target_id,
                result.timestamp.isoformat(),
                result.processed_at.isoformat() if result.processed_at else None,
                result.status,
                result.score,
                self._dict_to_json(result.details),
                self._dict_to_json(result.raw_data),
                result.notes
            )

            query = """
                    INSERT OR REPLACE INTO audit_results
                    (id, check_id, target_id, timestamp, processed_at, status, score, details, raw_data, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """

            self.cursor.execute(query, data)
            self.conn.commit()

            return result

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error saving result {result.id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_result(self, result_id: str) -> Optional[AuditResult]:
        """
        Retrieves an audit result from the database.

        Args:
        result_id: ID of the result to retrieve

        Returns:
        Result retrieved or None if not found
        """
        self._connect()

        try:
            query = "SELECT * FROM audit_results WHERE id = ?"

            self.cursor.execute(query, (result_id,))
            row = self.cursor.fetchone()

            if not row:
                return None

            result_dict = dict(row)

            result_dict["details"] = self._json_to_dict(result_dict["details"])
            result_dict["raw_data"] = self._json_to_dict(result_dict["raw_data"])

            return AuditResult.from_dict(result_dict)

        except sqlite3.Error as e:
            logger.error(f"Error retrieving result {result_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_results_by_check(self, check_id: str) -> List[AuditResult]:
        """
        Gets results for a specific check.

        Args:
        check_id: check ID

        Returns:
        List of results for the check
        """
        self._connect()

        try:
            query = "SELECT * FROM audit_results WHERE check_id = ? ORDER BY timestamp DESC"

            self.cursor.execute(query, (check_id,))
            rows = self.cursor.fetchall()

            results = []
            for row in rows:
                result_dict = dict(row)
                result_dict["details"] = self._json_to_dict(result_dict["details"])
                result_dict["raw_data"] = self._json_to_dict(result_dict["raw_data"])
                results.append(AuditResult.from_dict(result_dict))

            return results

        except sqlite3.Error as e:
            logger.error(f"Error retrieving results for check {check_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_results_by_target(self, target_id: str) -> List[AuditResult]:
        """
        Retrieve results for a specific target.

        Args:
            target_id: ID of the target

        Returns:
            List of results for the target
        """
        self._connect()

        try:
            query = "SELECT * FROM audit_results WHERE target_id = ? ORDER BY timestamp DESC"

            self.cursor.execute(query, (target_id,))
            rows = self.cursor.fetchall()

            results = []
            for row in rows:
                result_dict = dict(row)
                result_dict["details"] = self._json_to_dict(result_dict["details"])
                result_dict["raw_data"] = self._json_to_dict(result_dict["raw_data"])
                results.append(AuditResult.from_dict(result_dict))

            return results

        except sqlite3.Error as e:
            logger.error(f"Error retrieving results for target {target_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_latest_results(self, target_id: Optional[str] = None) -> List[AuditResult]:
        """
        Gets the most recent results, optionally filtered by target.

        Args:
        target_id: ID of the target (optional)

        Returns:
        List of most recent results
        """
        self._connect()

        try:
            query = """
                    SELECT * FROM audit_results r1
                    WHERE timestamp = (
                        SELECT MAX(timestamp)
                        FROM audit_results r2
                        WHERE r1.check_id = r2.check_id
                """

            params = []
            if target_id:
                query += " AND r2.target_id = ? AND r1.target_id = ?"
                params.extend([target_id, target_id])

            query += ") ORDER BY check_id"

            self.cursor.execute(query, params)
            rows = self.cursor.fetchall()

            results = []
            for row in rows:
                result_dict = dict(row)
                result_dict["details"] = self._json_to_dict(result_dict["details"])
                result_dict["raw_data"] = self._json_to_dict(result_dict["raw_data"])
                results.append(AuditResult.from_dict(result_dict))

            return results

        except sqlite3.Error as e:
            logger.error(f"Error retrieving latest results: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_filtered_results(self, target_ids: Optional[List[str]] = None,
                             check_ids: Optional[List[str]] = None) -> List[AuditResult]:
        """
        Gets results filtered by target and/or control.

        Args:
        target_ids: List of target IDs to filter (optional)
        check_ids: List of control IDs to filter (optional)

        Returns:
        List of filtered results
        """
        self._connect()

        try:
            query = "SELECT * FROM audit_results WHERE 1=1"
            params = []

            if target_ids:
                placeholders = ','.join(['?'] * len(target_ids))
                query += f" AND target_id IN ({placeholders})"
                params.extend(target_ids)

            if check_ids:
                placeholders = ','.join(['?'] * len(check_ids))
                query += f" AND check_id IN ({placeholders})"
                params.extend(check_ids)

            query += " ORDER BY timestamp DESC"

            self.cursor.execute(query, params)
            rows = self.cursor.fetchall()

            results = []
            for row in rows:
                result_dict = dict(row)
                result_dict["details"] = self._json_to_dict(result_dict["details"])
                result_dict["raw_data"] = self._json_to_dict(result_dict["raw_data"])
                results.append(AuditResult.from_dict(result_dict))

            return results

        except sqlite3.Error as e:
            logger.error(f"Error retrieving filtered results: {str(e)}")
            raise
        finally:
            self._disconnect()

    def delete_result(self, result_id: str) -> bool:
        """
        Deletes a result from the database.

        Args:
        result_id: ID of the result to delete

        Returns:
        True if the delete was successful, False otherwise
        """
        self._connect()

        try:
            query = "DELETE FROM audit_results WHERE id = ?"

            self.cursor.execute(query, (result_id,))
            self.conn.commit()

            return self.cursor.rowcount > 0

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error deleting result {result_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def delete_results_older_than(self, days: int) -> int:
        """
        Remove results older than a certain number of days.

        Args:
        days: Number of days

        Returns:
        Number of results removed
        """
        self._connect()

        try:
            cutoff_date = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat()

            query = "DELETE FROM audit_results WHERE timestamp < ?"

            self.cursor.execute(query, (cutoff_date,))
            self.conn.commit()

            return self.cursor.rowcount

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error deleting results older than {days} days: {str(e)}")
            raise
        finally:
            self._disconnect()

    # ----- Report Methods -----

    def save_report(self, report: AuditReport) -> AuditReport:
        """
        Save a report to the database.

        Args:
        report: Report to save

        Returns:
        Report saved
        """
        self._connect()

        try:
            data = (
                report.id,
                report.name,
                report.description,
                report.generated_at.isoformat(),
                self._list_to_json(report.target_ids),
                self._list_to_json(report.check_ids),
                self._dict_to_json(report.compliance_stats),
                self._dict_to_json(report.result_summary),
                self._list_to_json(report.result_ids),
                report.format
            )

            query = """
                    INSERT OR REPLACE INTO audit_reports
                    (id, name, description, generated_at, target_ids, check_ids, compliance_stats, result_summary, result_ids, format)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """

            self.cursor.execute(query, data)
            self.conn.commit()

            return report

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error saving report {report.id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_report(self, report_id: str) -> Optional[AuditReport]:
        """
        Retrieves a report from the database.

        Args:
        report_id: ID of the report to retrieve

        Returns:
        Report retrieved or None if not found
        """
        self._connect()

        try:
            query = "SELECT * FROM audit_reports WHERE id = ?"

            self.cursor.execute(query, (report_id,))
            row = self.cursor.fetchone()

            if not row:
                return None

            report_dict = dict(row)

            report_dict["target_ids"] = self._json_to_list(report_dict["target_ids"])
            report_dict["check_ids"] = self._json_to_list(report_dict["check_ids"])
            report_dict["compliance_stats"] = self._json_to_dict(report_dict["compliance_stats"])
            report_dict["result_summary"] = self._json_to_dict(report_dict["result_summary"])
            report_dict["result_ids"] = self._json_to_list(report_dict["result_ids"])

            return AuditReport.from_dict(report_dict)

        except sqlite3.Error as e:
            logger.error(f"Error retrieving report {report_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_all_reports(self) -> List[AuditReport]:
        """
        Retrieve all reports from the database.

        Returns:
        List of all reports
        """
        self._connect()

        try:
            query = "SELECT * FROM audit_reports ORDER BY generated_at DESC"

            self.cursor.execute(query)
            rows = self.cursor.fetchall()

            reports = []
            for row in rows:
                report_dict = dict(row)
                report_dict["target_ids"] = self._json_to_list(report_dict["target_ids"])
                report_dict["check_ids"] = self._json_to_list(report_dict["check_ids"])
                report_dict["compliance_stats"] = self._json_to_dict(report_dict["compliance_stats"])
                report_dict["result_summary"] = self._json_to_dict(report_dict["result_summary"])
                report_dict["result_ids"] = self._json_to_list(report_dict["result_ids"])
                reports.append(AuditReport.from_dict(report_dict))

            return reports

        except sqlite3.Error as e:
            logger.error(f"Error retrieving all reports: {str(e)}")
            raise
        finally:
            self._disconnect()

    def delete_report(self, report_id: str) -> bool:
        """
        Delete a report from the database.

        Args:
            report_id: ID of the report to delete

        Returns:
            True if the deletion was successful, False otherwise
        """
        self._connect()

        try:
            query = "DELETE FROM audit_reports WHERE id = ?"

            self.cursor.execute(query, (report_id,))
            self.conn.commit()

            return self.cursor.rowcount > 0

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error deleting report {report_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    # ----- Scheduled Audit Methods -----

    def save_scheduled_audit(self, scheduled: ScheduledAudit) -> ScheduledAudit:
        """
        Saves a scheduled audit to the database.

        Args:
        scheduled: Scheduled audit to save

        Returns:
        Scheduled audit saved
        """
        self._connect()

        try:
            data = (
                scheduled.id,
                scheduled.name,
                scheduled.description,
                self._list_to_json(scheduled.target_ids),
                self._list_to_json(scheduled.check_ids),
                scheduled.frequency,
                scheduled.day_of_week,
                scheduled.day_of_month,
                scheduled.hour,
                scheduled.minute,
                int(scheduled.enabled),
                scheduled.last_run.isoformat() if scheduled.last_run else None,
                scheduled.next_run.isoformat() if scheduled.next_run else None,
                int(scheduled.notify_on_completion),
                scheduled.notify_email,
                self._dict_to_json(scheduled.params)
            )

            query = """
                    INSERT OR REPLACE INTO scheduled_audits
                    (id, name, description, target_ids, check_ids, frequency, day_of_week, day_of_month, hour, minute, 
                    enabled, last_run, next_run, notify_on_completion, notify_email, params)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """

            self.cursor.execute(query, data)
            self.conn.commit()

            return scheduled

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error saving scheduled audit {scheduled.id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_scheduled_audit(self, scheduled_id: str) -> Optional[ScheduledAudit]:
        """
        Retrieves a scheduled audit from the database.

        Args:
        scheduled_id: ID of the scheduled audit to retrieve

        Returns:
        Scheduled audit retrieved or None if not found
        """
        self._connect()

        try:
            query = "SELECT * FROM scheduled_audits WHERE id = ?"

            self.cursor.execute(query, (scheduled_id,))
            row = self.cursor.fetchone()

            if not row:
                return None

            scheduled_dict = dict(row)

            scheduled_dict["enabled"] = bool(scheduled_dict["enabled"])
            scheduled_dict["notify_on_completion"] = bool(scheduled_dict["notify_on_completion"])
            scheduled_dict["target_ids"] = self._json_to_list(scheduled_dict["target_ids"])
            scheduled_dict["check_ids"] = self._json_to_list(scheduled_dict["check_ids"])
            scheduled_dict["params"] = self._json_to_dict(scheduled_dict["params"])

            return ScheduledAudit.from_dict(scheduled_dict)

        except sqlite3.Error as e:
            logger.error(f"Error retrieving scheduled audit {scheduled_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_all_scheduled_audits(self) -> List[ScheduledAudit]:
        """
        Retrieves all scheduled audits from the database.

        Returns:
        List of all scheduled audits
        """
        self._connect()

        try:
            query = "SELECT * FROM scheduled_audits ORDER BY next_run"

            self.cursor.execute(query)
            rows = self.cursor.fetchall()

            scheduled_audits = []
            for row in rows:
                scheduled_dict = dict(row)
                scheduled_dict["enabled"] = bool(scheduled_dict["enabled"])
                scheduled_dict["notify_on_completion"] = bool(scheduled_dict["notify_on_completion"])
                scheduled_dict["target_ids"] = self._json_to_list(scheduled_dict["target_ids"])
                scheduled_dict["check_ids"] = self._json_to_list(scheduled_dict["check_ids"])
                scheduled_dict["params"] = self._json_to_dict(scheduled_dict["params"])
                scheduled_audits.append(ScheduledAudit.from_dict(scheduled_dict))

            return scheduled_audits

        except sqlite3.Error as e:
            logger.error(f"Error retrieving all scheduled audits: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_due_scheduled_audits(self) -> List[ScheduledAudit]:
        """
        Retrieves scheduled audits that need to be run.

        Returns:
        List of scheduled audits to run
        """
        self._connect()

        try:
            now = datetime.datetime.now().isoformat()

            query = "SELECT * FROM scheduled_audits WHERE enabled = 1 AND next_run <= ? ORDER BY next_run"

            self.cursor.execute(query, (now,))
            rows = self.cursor.fetchall()

            scheduled_audits = []
            for row in rows:
                scheduled_dict = dict(row)
                scheduled_dict["enabled"] = bool(scheduled_dict["enabled"])
                scheduled_dict["notify_on_completion"] = bool(scheduled_dict["notify_on_completion"])
                scheduled_dict["target_ids"] = self._json_to_list(scheduled_dict["target_ids"])
                scheduled_dict["check_ids"] = self._json_to_list(scheduled_dict["check_ids"])
                scheduled_dict["params"] = self._json_to_dict(scheduled_dict["params"])
                scheduled_audits.append(ScheduledAudit.from_dict(scheduled_dict))

            return scheduled_audits

        except sqlite3.Error as e:
            logger.error(f"Error retrieving due scheduled audits: {str(e)}")
            raise
        finally:
            self._disconnect()

    def delete_scheduled_audit(self, scheduled_id: str) -> bool:
        """
        Deletes a scheduled audit from the database.

        Args:
        scheduled_id: ID of the scheduled audit to delete

        Returns:
        True if the deletion was successful, False otherwise
        """
        self._connect()

        try:
            query = "DELETE FROM scheduled_audits WHERE id = ?"

            self.cursor.execute(query, (scheduled_id,))
            self.conn.commit()

            return self.cursor.rowcount > 0

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error deleting scheduled audit {scheduled_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    # ----- User Account Methods -----

    def save_user(self, user: UserAccount) -> UserAccount:
        """
        Saves a user account to the database.

        Args:
        user: User account to save

        Returns:
        Saved user account
        """
        self._connect()

        try:
            user.updated_at = datetime.datetime.now()

            data = (
                user.id,
                user.username,
                user.password_hash,
                user.email,
                user.first_name,
                user.last_name,
                user.role,
                int(user.enabled),
                user.last_login.isoformat() if user.last_login else None,
                user.created_at.isoformat(),
                user.updated_at.isoformat(),
                self._dict_to_json(user.preferences)
            )

            query = """
                    INSERT OR REPLACE INTO user_accounts
                    (id, username, password_hash, email, first_name, last_name, role, enabled, 
                    last_login, created_at, updated_at, preferences)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """

            self.cursor.execute(query, data)
            self.conn.commit()

            return user

        except sqlite3.Error as e:
            self.conn.rollback

    def get_all_users(self) -> List['UserAccount']:
        """
        Retrieve all users from the database.

        Returns:
        List of all users
        """
        self._connect()

        try:
            query = "SELECT * FROM user_accounts ORDER BY username"

            self.cursor.execute(query)
            rows = self.cursor.fetchall()

            users = []
            for row in rows:
                user_dict = dict(row)
                user_dict["enabled"] = bool(user_dict["enabled"])
                user_dict["preferences"] = self._json_to_dict(user_dict["preferences"])
                users.append(UserAccount.from_dict(user_dict))

            return users

        except sqlite3.Error as e:
            logger.error(f"Error retrieving all users: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_users_by_username(self, username: str) -> List['UserAccount']:
        """
        Gets users with a given username.

        Args:
        username: Username to search

        Returns:
        List of users found (usually will be at most one)
        """
        self._connect()

        try:
            query = "SELECT * FROM user_accounts WHERE username = ?"

            self.cursor.execute(query, (username,))
            rows = self.cursor.fetchall()

            users = []
            for row in rows:
                user_dict = dict(row)
                user_dict["enabled"] = bool(user_dict["enabled"])
                user_dict["preferences"] = self._json_to_dict(user_dict["preferences"])
                users.append(UserAccount.from_dict(user_dict))

            return users

        except sqlite3.Error as e:
            logger.error(f"Error retrieving user by username {username}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_user(self, user_id: str) -> Optional['UserAccount']:
        """
        Retrieves a user from the database.

        Args:
        user_id: ID of the user to retrieve

        Returns:
        Retrieved user or None if not found
        """
        self._connect()

        try:
            query = "SELECT * FROM user_accounts WHERE id = ?"

            self.cursor.execute(query, (user_id,))
            row = self.cursor.fetchone()

            if not row:
                return None

            user_dict = dict(row)
            user_dict["enabled"] = bool(user_dict["enabled"])
            user_dict["preferences"] = self._json_to_dict(user_dict["preferences"])

            return UserAccount.from_dict(user_dict)

        except sqlite3.Error as e:
            logger.error(f"Error retrieving user {user_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def delete_user(self, user_id: str) -> bool:
        """
        Deletes a user from the database.

        Args:
        user_id: ID of the user to delete

        Returns:
        True if the deletion was successful, False otherwise
        """
        self._connect()

        try:
            query = "DELETE FROM user_accounts WHERE id = ?"

            self.cursor.execute(query, (user_id,))
            self.conn.commit()

            return self.cursor.rowcount > 0

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error deleting user {user_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    # ----- Network Methods -----

    def save_network_scan(self, network_scan: NetworkScan):
        """
        Save a network scan to the database.

        Args:
            network_scan: NetworkScan instance to save
        """
        self._connect()

        try:
            scan_data = network_scan.to_dict()

            query = '''
            INSERT OR REPLACE INTO network_scans (
                id, name, description, start_time, end_time, 
                network_ranges, scan_parameters, 
                total_devices, total_open_ports, total_vulnerabilities
            ) VALUES (
                :id, :name, :description, :start_time, :end_time, 
                :network_ranges, :scan_parameters, 
                :total_devices, :total_open_ports, :total_vulnerabilities
            )
            '''

            self.cursor.execute(query, scan_data)
            self.conn.commit()

        except sqlite3.Error as e:
            logger.error(f"Error saving network scan: {e}")
            self.conn.rollback()
            raise

    def update_network_scan(self, network_scan: NetworkScan):
        """
        Update an existing network scan.

        Args:
            network_scan: NetworkScan instance to update
        """
        self._connect()

        try:
            scan_data = network_scan.to_dict()

            query = '''
            UPDATE network_scans SET
                name = :name,
                description = :description,
                end_time = :end_time,
                total_devices = :total_devices,
                total_open_ports = :total_open_ports,
                total_vulnerabilities = :total_vulnerabilities
            WHERE id = :id
            '''

            self.cursor.execute(query, scan_data)
            self.conn.commit()

        except sqlite3.Error as e:
            logger.error(f"Error updating network scan: {e}")
            self.conn.rollback()
            raise

    def get_network_scan(self, scan_id: str) -> Optional[NetworkScan]:
        """
        Retrieve a network scan from the database.

        Args:
            scan_id: ID of the scan to retrieve

        Returns:
            NetworkScan instance or None if not found
        """
        self._connect()

        try:
            query = 'SELECT * FROM network_scans WHERE id = ?'
            self.cursor.execute(query, (scan_id,))

            row = self.cursor.fetchone()

            if row:
                scan_dict = dict(zip([col[0] for col in self.cursor.description], row))
                return NetworkScan.from_dict(scan_dict)

            return None

        except sqlite3.Error as e:
            logger.error(f"Error retrieving network scan: {e}")
            raise

    def save_network_devices(self, devices: List[NetworkDevice]):
        """
        Save a list of network devices to the database.

        Args:
            devices: List of NetworkDevice instances to save
        """
        self._connect()

        try:
            query = '''
            INSERT OR REPLACE INTO network_devices (
                id, scan_id, ip, mac, hostname, os, os_version,
                services, is_alive, reachable_protocols, 
                potential_vulnerabilities, open_ports, 
                closed_ports, filtered_ports, additional_info,
                first_seen, last_seen
            ) VALUES (
                :id, :scan_id, :ip, :mac, :hostname, :os, :os_version,
                :services, :is_alive, :reachable_protocols, 
                :potential_vulnerabilities, :open_ports, 
                :closed_ports, :filtered_ports, :additional_info,
                :first_seen, :last_seen
            )
            '''

            for device in devices:
                device_data = device.to_dict()
                self.cursor.execute(query, device_data)

            self.conn.commit()

        except sqlite3.Error as e:
            logger.error(f"Error saving network devices: {e}")
            self.conn.rollback()
            raise

    def get_network_devices(self,
                            scan_id: Optional[str] = None,
                            ip: Optional[str] = None,
                            hostname: Optional[str] = None,
                            limit: int = 100,
                            offset: int = 0) -> List[NetworkDevice]:
        """
        Retrieve network devices with filtering options.

        Args:
            scan_id: Filter by scan ID
            ip: Filter by IP address
            hostname: Filter by hostname
            limit: Maximum number of results
            offset: Offset for pagination

        Returns:
            List of network devices
        """
        self._connect()

        try:
            conditions = []
            params = []

            if scan_id:
                conditions.append('scan_id = ?')
                params.append(scan_id)

            if ip:
                conditions.append('ip = ?')
                params.append(ip)

            if hostname:
                conditions.append('hostname LIKE ?')
                params.append(f'%{hostname}%')

            where_clause = 'WHERE ' + ' AND '.join(conditions) if conditions else ''
            query = f'''
            SELECT * FROM network_devices 
            {where_clause}
            LIMIT ? OFFSET ?
            '''

            params.extend([limit, offset])

            self.cursor.execute(query, params)

            devices = []
            for row in self.cursor.fetchall():
                device_dict = dict(zip([col[0] for col in self.cursor.description], row))
                devices.append(NetworkDevice.from_dict(device_dict))

            return devices

        except sqlite3.Error as e:
            logger.error(f"Error retrieving network devices: {e}")
            raise

    def delete_network_scan(self, scan_id: str):
        """
        Delete a network scan and its related devices.

        Args:
            scan_id: ID of the scan to delete
        """
        self._connect()

        try:
            self.cursor.execute('DELETE FROM network_devices WHERE scan_id = ?', (scan_id,))

            self.cursor.execute('DELETE FROM network_scans WHERE id = ?', (scan_id,))

            self.conn.commit()

        except sqlite3.Error as e:
            logger.error(f"Error deleting network scan: {e}")
            self.conn.rollback()
            raise

    #  ----- Init db Methods -----

    def init_db(self):
        """
        Initializes the database by creating all the necessary tables.

        Returns:
        True if initialization succeeds, False otherwise
        """
        try:
            self._initialize_db()
            return True
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            return False