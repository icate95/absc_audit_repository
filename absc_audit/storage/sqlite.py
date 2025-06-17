"""
     SQLite Storage Backend - Implementazione del backend di storage basato su SQLite.

     Questo modulo implementa il backend di persistenza dati utilizzando SQLite
     per archiviare target, controlli e risultati degli audit.
     """

import json
import os
import threading
import sqlite3
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple

from absc_audit.storage.models import Target, AuditCheck, AuditResult, AuditReport, ScheduledAudit, UserAccount
from absc_audit.config.settings import Settings
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class SQLiteStorage:
    """
    Backend di storage basato su SQLite.

    Questa classe gestisce la persistenza dei dati utilizzando un database SQLite.
    Supporta tutte le operazioni CRUD per i modelli dati del sistema.
    """

    # Thread local storage per connessioni thread-specifiche
    _thread_local = threading.local()

    def __init__(self, settings: Optional[Settings] = None, db_path: Optional[str] = None):
        """
        Inizializza il backend di storage SQLite.

        Args:
            settings: Configurazioni del sistema (opzionale)
            db_path: Percorso del file di database (opzionale)
        """
        self.settings = settings or Settings()
        self.db_path = db_path or self.settings.sqlite_path or "audit_data.db"

        # Assicura che la directory esista
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)

        # Inizializza il database
        self._initialize_db()

    def _initialize_db(self):
        """Inizializza il database creando tabelle se non esistono."""
        self._connect()

        # Definizione delle tabelle
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

        # Crea le tabelle
        for table_name, table_schema in tables.items():
            try:
                self.cursor.execute(table_schema)
            except sqlite3.Error as e:
                logger.error(f"Error creating table {table_name}: {str(e)}")

        # Crea indici per migliorare le performance
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_audit_results_check_id ON audit_results(check_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_results_target_id ON audit_results(target_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_results_timestamp ON audit_results(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_targets_name ON targets(name)",
            "CREATE INDEX IF NOT EXISTS idx_targets_hostname ON targets(hostname)",
            "CREATE INDEX IF NOT EXISTS idx_targets_ip_address ON targets(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_user_accounts_username ON user_accounts(username)"
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
        Stabilisce una connessione al database specifica per il thread corrente.

        Ogni thread avrà la sua connessione dedicata al database.
        """
        try:
            # Verifica se il thread corrente ha già una connessione
            if not hasattr(self._thread_local, 'conn') or self._thread_local.conn is None:
                # Crea una nuova connessione per questo thread
                self._thread_local.conn = sqlite3.connect(self.db_path)
                # Abilita il supporto alle foreign key
                self._thread_local.conn.execute("PRAGMA foreign_keys = ON")
                # Configura il ritorno di dict invece di tuple
                self._thread_local.conn.row_factory = sqlite3.Row
                self._thread_local.cursor = self._thread_local.conn.cursor()

            # Riferimenti locali per comodità
            self.conn = self._thread_local.conn
            self.cursor = self._thread_local.cursor
        except sqlite3.Error as e:
            logger.error(f"Error connecting to SQLite database: {str(e)}")
            raise

    def _disconnect(self):
        """
        "Disconnette" dal database.

        In realtà manteniamo la connessione aperta per il thread,
        ma resettiamo i riferimenti locali.
        """
        self.conn = None
        self.cursor = None

    def close_all(self):
        """
        Chiude tutte le connessioni al database.

        Questo metodo dovrebbe essere chiamato quando l'applicazione termina.
        """
        try:
            if hasattr(self._thread_local, 'conn') and self._thread_local.conn:
                self._thread_local.conn.close()
                self._thread_local.conn = None
                self._thread_local.cursor = None
        except sqlite3.Error as e:
            logger.error(f"Error closing SQLite connection: {str(e)}")

    def _dict_to_json(self, data: Dict) -> str:
        """Converte un dizionario in una stringa JSON."""
        if not data:
            return "{}"
        return json.dumps(data, default=str)

    def _json_to_dict(self, json_str: str) -> Dict:
        """Converte una stringa JSON in un dizionario."""
        if not json_str or json_str == "{}":
            return {}
        return json.loads(json_str)

    def _list_to_json(self, data: List) -> str:
        """Converte una lista in una stringa JSON."""
        if not data:
            return "[]"
        return json.dumps(data, default=str)

    def _json_to_list(self, json_str: str) -> List:
        """Converte una stringa JSON in una lista."""
        if not json_str or json_str == "[]":
            return []
        return json.loads(json_str)

    # ----- Target Methods -----

    def save_target(self, target: Target) -> Target:
        """
        Salva un target nel database.

        Args:
            target: Target da salvare

        Returns:
            Target salvato
        """
        self._connect()

        try:
            # Aggiorna il timestamp di modifica
            target.updated_at = datetime.datetime.now()

            # Prepara i dati da salvare
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

            # Query di insert/update
            query = """
                INSERT OR REPLACE INTO targets
                (id, name, hostname, ip_address, os_type, os_version, description, "group", tags, attributes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """

            # Esegui la query
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
        Recupera un target dal database.

        Args:
            target_id: ID del target da recuperare

        Returns:
            Target recuperato o None se non trovato
        """
        self._connect()

        try:
            # Query per recuperare il target
            query = "SELECT * FROM targets WHERE id = ?"

            # Esegui la query
            self.cursor.execute(query, (target_id,))
            row = self.cursor.fetchone()

            if not row:
                return None

            # Converti il risultato in un dizionario
            target_dict = dict(row)

            # Converti le liste e i dizionari da JSON
            target_dict["tags"] = self._json_to_list(target_dict["tags"])
            target_dict["attributes"] = self._json_to_dict(target_dict["attributes"])

            # Crea l'oggetto Target
            return Target.from_dict(target_dict)

        except sqlite3.Error as e:
            logger.error(f"Error retrieving target {target_id}: {str(e)}")
            raise
        finally:
            # Non chiudiamo la connessione
            pass

    def get_all_targets(self) -> List[Target]:
        """
        Recupera tutti i target dal database.

        Returns:
            Lista di tutti i target
        """
        self._connect()

        try:
            # Query per recuperare tutti i target
            query = "SELECT * FROM targets ORDER BY name"

            # Esegui la query
            self.cursor.execute(query)
            rows = self.cursor.fetchall()

            # Converti i risultati in oggetti Target
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
        Recupera i target di un gruppo specifico.

        Args:
            group: Nome del gruppo

        Returns:
            Lista di target nel gruppo
        """
        self._connect()

        try:
            # Query per recuperare i target del gruppo
            query = "SELECT * FROM targets WHERE \"group\" = ? ORDER BY name"

            # Esegui la query
            self.cursor.execute(query, (group,))
            rows = self.cursor.fetchall()

            # Converti i risultati in oggetti Target
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
        Recupera i target con un tag specifico.

        Args:
            tag: Tag da cercare

        Returns:
            Lista di target con il tag
        """
        self._connect()

        try:
            # Query per recuperare i target con il tag
            # Utilizziamo LIKE con il tag in formato JSON
            query = "SELECT * FROM targets WHERE tags LIKE ? ORDER BY name"

            # Esegui la query
            self.cursor.execute(query, (f'%"{tag}"%',))
            rows = self.cursor.fetchall()

            # Converti i risultati in oggetti Target
            targets = []
            for row in rows:
                target_dict = dict(row)
                tags = self._json_to_list(target_dict["tags"])
                # Verifica che il tag sia effettivamente presente (non solo in una stringa)
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
        Elimina un target dal database.

        Args:
            target_id: ID del target da eliminare

        Returns:
            True se l'eliminazione ha avuto successo, False altrimenti
        """
        self._connect()

        try:
            # Query per eliminare il target
            query = "DELETE FROM targets WHERE id = ?"

            # Esegui la query
            self.cursor.execute(query, (target_id,))
            self.conn.commit()

            # Verifica se è stato eliminato qualcosa
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
        Salva un controllo nel database.

        Args:
            check: Controllo da salvare

        Returns:
            Controllo salvato
        """
        self._connect()

        try:
            # Prepara i dati da salvare
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

            # Query di insert/update
            query = """
                INSERT OR REPLACE INTO audit_checks
                (id, name, description, question, possible_answers, category, priority, enabled, params)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """

            # Esegui la query
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
        Recupera un controllo dal database.

        Args:
            check_id: ID del controllo da recuperare

        Returns:
            Controllo recuperato o None se non trovato
        """
        self._connect()

        try:
            # Query per recuperare il controllo
            query = "SELECT * FROM audit_checks WHERE id = ?"

            # Esegui la query
            self.cursor.execute(query, (check_id,))
            row = self.cursor.fetchone()

            if not row:
                return None

            # Converti il risultato in un dizionario
            check_dict = dict(row)

            # Converti boolean e liste
            check_dict["enabled"] = bool(check_dict["enabled"])
            check_dict["possible_answers"] = self._json_to_list(check_dict["possible_answers"])
            check_dict["params"] = self._json_to_dict(check_dict["params"])

            # Crea l'oggetto AuditCheck
            return AuditCheck.from_dict(check_dict)

        except sqlite3.Error as e:
            logger.error(f"Error retrieving check {check_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_all_checks(self) -> List[AuditCheck]:
        """
        Recupera tutti i controlli dal database.

        Returns:
            Lista di tutti i controlli
        """
        self._connect()

        try:
            # Query per recuperare tutti i controlli
            query = "SELECT * FROM audit_checks ORDER BY id"

            # Esegui la query
            self.cursor.execute(query)
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
            logger.error(f"Error retrieving all checks: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_checks_by_category(self, category: str) -> List[AuditCheck]:
        """
        Recupera i controlli di una categoria specifica.

        Args:
            category: Categoria da cercare

        Returns:
            Lista di controlli nella categoria
        """
        self._connect()

        try:
            # Query per recuperare i controlli della categoria
            query = "SELECT * FROM audit_checks WHERE category = ? ORDER BY id"

            # Esegui la query
            self.cursor.execute(query, (category,))
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
            logger.error(f"Error retrieving checks in category {category}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_checks_by_priority(self, priority: int) -> List[AuditCheck]:
        """
        Recupera i controlli con una priorità specifica.

        Args:
            priority: Priorità da cercare (1=alta, 2=media, 3=bassa)

        Returns:
            Lista di controlli con la priorità specificata
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
        Elimina un controllo dal database.

        Args:
            check_id: ID del controllo da eliminare

        Returns:
            True se l'eliminazione ha avuto successo, False altrimenti
        """
        self._connect()

        try:
            # Query per eliminare il controllo
            query = "DELETE FROM audit_checks WHERE id = ?"

            # Esegui la query
            self.cursor.execute(query, (check_id,))
            self.conn.commit()

            # Verifica se è stato eliminato qualcosa
            return self.cursor.rowcount > 0

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error deleting check {check_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

        # ----- Audit Result Methods -----

    def save_result(self, result: AuditResult) -> AuditResult:
        """
        Salva un risultato di audit nel database.

        Args:
            result: Risultato da salvare

        Returns:
            Risultato salvato
        """
        self._connect()

        try:
            # Prepara i dati da salvare
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

            # Query di insert/update
            query = """
                    INSERT OR REPLACE INTO audit_results
                    (id, check_id, target_id, timestamp, processed_at, status, score, details, raw_data, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """

            # Esegui la query
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
        Recupera un risultato di audit dal database.

        Args:
            result_id: ID del risultato da recuperare

        Returns:
            Risultato recuperato o None se non trovato
        """
        self._connect()

        try:
            # Query per recuperare il risultato
            query = "SELECT * FROM audit_results WHERE id = ?"

            # Esegui la query
            self.cursor.execute(query, (result_id,))
            row = self.cursor.fetchone()

            if not row:
                return None

            # Converti il risultato in un dizionario
            result_dict = dict(row)

            # Converti i dizionari da JSON
            result_dict["details"] = self._json_to_dict(result_dict["details"])
            result_dict["raw_data"] = self._json_to_dict(result_dict["raw_data"])

            # Crea l'oggetto AuditResult
            return AuditResult.from_dict(result_dict)

        except sqlite3.Error as e:
            logger.error(f"Error retrieving result {result_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_results_by_check(self, check_id: str) -> List[AuditResult]:
        """
        Recupera i risultati per un controllo specifico.

        Args:
            check_id: ID del controllo

        Returns:
            Lista di risultati per il controllo
        """
        self._connect()

        try:
            # Query per recuperare i risultati del controllo
            query = "SELECT * FROM audit_results WHERE check_id = ? ORDER BY timestamp DESC"

            # Esegui la query
            self.cursor.execute(query, (check_id,))
            rows = self.cursor.fetchall()

            # Converti i risultati in oggetti AuditResult
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
        Recupera i risultati per un target specifico.

        Args:
            target_id: ID del target

        Returns:
            Lista di risultati per il target
        """
        self._connect()

        try:
            # Query per recuperare i risultati del target
            query = "SELECT * FROM audit_results WHERE target_id = ? ORDER BY timestamp DESC"

            # Esegui la query
            self.cursor.execute(query, (target_id,))
            rows = self.cursor.fetchall()

            # Converti i risultati in oggetti AuditResult
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
        Recupera i risultati più recenti, opzionalmente filtrati per target.

        Args:
            target_id: ID del target (opzionale)

        Returns:
            Lista di risultati più recenti
        """
        self._connect()

        try:
            # Query di base
            query = """
                    SELECT * FROM audit_results r1
                    WHERE timestamp = (
                        SELECT MAX(timestamp)
                        FROM audit_results r2
                        WHERE r1.check_id = r2.check_id
                """

            # Aggiungi il filtro per target se specificato
            params = []
            if target_id:
                query += " AND r2.target_id = ? AND r1.target_id = ?"
                params.extend([target_id, target_id])

            query += ") ORDER BY check_id"

            # Esegui la query
            self.cursor.execute(query, params)
            rows = self.cursor.fetchall()

            # Converti i risultati in oggetti AuditResult
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
        Recupera i risultati filtrati per target e/o controllo.

        Args:
            target_ids: Lista di ID target da filtrare (opzionale)
            check_ids: Lista di ID controllo da filtrare (opzionale)

        Returns:
            Lista di risultati filtrati
        """
        self._connect()

        try:
            # Costruisci la query di base
            query = "SELECT * FROM audit_results WHERE 1=1"
            params = []

            # Aggiungi il filtro per target se specificato
            if target_ids:
                placeholders = ','.join(['?'] * len(target_ids))
                query += f" AND target_id IN ({placeholders})"
                params.extend(target_ids)

            # Aggiungi il filtro per controllo se specificato
            if check_ids:
                placeholders = ','.join(['?'] * len(check_ids))
                query += f" AND check_id IN ({placeholders})"
                params.extend(check_ids)

            # Ordina per timestamp decrescente
            query += " ORDER BY timestamp DESC"

            # Esegui la query
            self.cursor.execute(query, params)
            rows = self.cursor.fetchall()

            # Converti i risultati in oggetti AuditResult
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
        Elimina un risultato dal database.

        Args:
            result_id: ID del risultato da eliminare

        Returns:
            True se l'eliminazione ha avuto successo, False altrimenti
        """
        self._connect()

        try:
            # Query per eliminare il risultato
            query = "DELETE FROM audit_results WHERE id = ?"

            # Esegui la query
            self.cursor.execute(query, (result_id,))
            self.conn.commit()

            # Verifica se è stato eliminato qualcosa
            return self.cursor.rowcount > 0

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error deleting result {result_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def delete_results_older_than(self, days: int) -> int:
        """
        Elimina i risultati più vecchi di un certo numero di giorni.

        Args:
            days: Numero di giorni

        Returns:
            Numero di risultati eliminati
        """
        self._connect()

        try:
            # Calcola la data limite
            cutoff_date = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat()

            # Query per eliminare i risultati
            query = "DELETE FROM audit_results WHERE timestamp < ?"

            # Esegui la query
            self.cursor.execute(query, (cutoff_date,))
            self.conn.commit()

            # Restituisci il numero di righe eliminate
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
        Salva un report nel database.

        Args:
            report: Report da salvare

        Returns:
            Report salvato
        """
        self._connect()

        try:
            # Prepara i dati da salvare
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

            # Query di insert/update
            query = """
                    INSERT OR REPLACE INTO audit_reports
                    (id, name, description, generated_at, target_ids, check_ids, compliance_stats, result_summary, result_ids, format)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """

            # Esegui la query
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
        Recupera un report dal database.

        Args:
            report_id: ID del report da recuperare

        Returns:
            Report recuperato o None se non trovato
        """
        self._connect()

        try:
            # Query per recuperare il report
            query = "SELECT * FROM audit_reports WHERE id = ?"

            # Esegui la query
            self.cursor.execute(query, (report_id,))
            row = self.cursor.fetchone()

            if not row:
                return None

            # Converti il risultato in un dizionario
            report_dict = dict(row)

            # Converti liste e dizionari da JSON
            report_dict["target_ids"] = self._json_to_list(report_dict["target_ids"])
            report_dict["check_ids"] = self._json_to_list(report_dict["check_ids"])
            report_dict["compliance_stats"] = self._json_to_dict(report_dict["compliance_stats"])
            report_dict["result_summary"] = self._json_to_dict(report_dict["result_summary"])
            report_dict["result_ids"] = self._json_to_list(report_dict["result_ids"])

            # Crea l'oggetto AuditReport
            return AuditReport.from_dict(report_dict)

        except sqlite3.Error as e:
            logger.error(f"Error retrieving report {report_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_all_reports(self) -> List[AuditReport]:
        """
        Recupera tutti i report dal database.

        Returns:
            Lista di tutti i report
        """
        self._connect()

        try:
            # Query per recuperare tutti i report
            query = "SELECT * FROM audit_reports ORDER BY generated_at DESC"

            # Esegui la query
            self.cursor.execute(query)
            rows = self.cursor.fetchall()

            # Converti i risultati in oggetti AuditReport
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
        Elimina un report dal database.

        Args:
            report_id: ID del report da eliminare

        Returns:
            True se l'eliminazione ha avuto successo, False altrimenti
        """
        self._connect()

        try:
            # Query per eliminare il report
            query = "DELETE FROM audit_reports WHERE id = ?"

            # Esegui la query
            self.cursor.execute(query, (report_id,))
            self.conn.commit()

            # Verifica se è stato eliminato qualcosa
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
        Salva un audit pianificato nel database.

        Args:
            scheduled: Audit pianificato da salvare

        Returns:
            Audit pianificato salvato
        """
        self._connect()

        try:
            # Prepara i dati da salvare
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

            # Query di insert/update
            query = """
                    INSERT OR REPLACE INTO scheduled_audits
                    (id, name, description, target_ids, check_ids, frequency, day_of_week, day_of_month, hour, minute, 
                    enabled, last_run, next_run, notify_on_completion, notify_email, params)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """

            # Esegui la query
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
        Recupera un audit pianificato dal database.

        Args:
            scheduled_id: ID dell'audit pianificato da recuperare

        Returns:
            Audit pianificato recuperato o None se non trovato
        """
        self._connect()

        try:
            # Query per recuperare l'audit pianificato
            query = "SELECT * FROM scheduled_audits WHERE id = ?"

            # Esegui la query
            self.cursor.execute(query, (scheduled_id,))
            row = self.cursor.fetchone()

            if not row:
                return None

            # Converti il risultato in un dizionario
            scheduled_dict = dict(row)

            # Converti boolean, liste e dizionari
            scheduled_dict["enabled"] = bool(scheduled_dict["enabled"])
            scheduled_dict["notify_on_completion"] = bool(scheduled_dict["notify_on_completion"])
            scheduled_dict["target_ids"] = self._json_to_list(scheduled_dict["target_ids"])
            scheduled_dict["check_ids"] = self._json_to_list(scheduled_dict["check_ids"])
            scheduled_dict["params"] = self._json_to_dict(scheduled_dict["params"])

            # Crea l'oggetto ScheduledAudit
            return ScheduledAudit.from_dict(scheduled_dict)

        except sqlite3.Error as e:
            logger.error(f"Error retrieving scheduled audit {scheduled_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def get_all_scheduled_audits(self) -> List[ScheduledAudit]:
        """
        Recupera tutti gli audit pianificati dal database.

        Returns:
            Lista di tutti gli audit pianificati
        """
        self._connect()

        try:
            # Query per recuperare tutti gli audit pianificati
            query = "SELECT * FROM scheduled_audits ORDER BY next_run"

            # Esegui la query
            self.cursor.execute(query)
            rows = self.cursor.fetchall()

            # Converti i risultati in oggetti ScheduledAudit
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
        Recupera gli audit pianificati che devono essere eseguiti.

        Returns:
            Lista di audit pianificati da eseguire
        """
        self._connect()

        try:
            # Ottieni la data e ora corrente
            now = datetime.datetime.now().isoformat()

            # Query per recuperare gli audit pianificati da eseguire
            query = "SELECT * FROM scheduled_audits WHERE enabled = 1 AND next_run <= ? ORDER BY next_run"

            # Esegui la query
            self.cursor.execute(query, (now,))
            rows = self.cursor.fetchall()

            # Converti i risultati in oggetti ScheduledAudit
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
        Elimina un audit pianificato dal database.

        Args:
            scheduled_id: ID dell'audit pianificato da eliminare

        Returns:
            True se l'eliminazione ha avuto successo, False altrimenti
        """
        self._connect()

        try:
            # Query per eliminare l'audit pianificato
            query = "DELETE FROM scheduled_audits WHERE id = ?"

            # Esegui la query
            self.cursor.execute(query, (scheduled_id,))
            self.conn.commit()

            # Verifica se è stato eliminato qualcosa
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
        Salva un account utente nel database.

        Args:
            user: Account utente da salvare

        Returns:
            Account utente salvato
        """
        self._connect()

        try:
            # Aggiorna il timestamp di modifica
            user.updated_at = datetime.datetime.now()

            # Prepara i dati da salvare
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

            # Query di insert/update
            query = """
                    INSERT OR REPLACE INTO user_accounts
                    (id, username, password_hash, email, first_name, last_name, role, enabled, 
                    last_login, created_at, updated_at, preferences)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """

            # Esegui la query
            self.cursor.execute(query, data)
            self.conn.commit()

            return user

        except sqlite3.Error as e:
            self.conn.rollback

    def get_all_users(self) -> List['UserAccount']:
        """
        Recupera tutti gli utenti dal database.

        Returns:
            Lista di tutti gli utenti
        """
        self._connect()

        try:
            # Query per recuperare tutti gli utenti
            query = "SELECT * FROM user_accounts ORDER BY username"

            # Esegui la query
            self.cursor.execute(query)
            rows = self.cursor.fetchall()

            # Converti i risultati in oggetti UserAccount
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
        Recupera gli utenti con un certo username.

        Args:
            username: Username da cercare

        Returns:
            Lista di utenti trovati (normalmente sarà al massimo uno)
        """
        self._connect()

        try:
            # Query per recuperare l'utente
            query = "SELECT * FROM user_accounts WHERE username = ?"

            # Esegui la query
            self.cursor.execute(query, (username,))
            rows = self.cursor.fetchall()

            # Converti i risultati in oggetti UserAccount
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
        Recupera un utente dal database.

        Args:
            user_id: ID dell'utente da recuperare

        Returns:
            Utente recuperato o None se non trovato
        """
        self._connect()

        try:
            # Query per recuperare l'utente
            query = "SELECT * FROM user_accounts WHERE id = ?"

            # Esegui la query
            self.cursor.execute(query, (user_id,))
            row = self.cursor.fetchone()

            if not row:
                return None

            # Converti il risultato in un oggetto UserAccount
            user_dict = dict(row)
            user_dict["enabled"] = bool(user_dict["enabled"])
            user_dict["preferences"] = self._json_to_dict(user_dict["preferences"])

            # Crea l'oggetto UserAccount
            return UserAccount.from_dict(user_dict)

        except sqlite3.Error as e:
            logger.error(f"Error retrieving user {user_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    def delete_user(self, user_id: str) -> bool:
        """
        Elimina un utente dal database.

        Args:
            user_id: ID dell'utente da eliminare

        Returns:
            True se l'eliminazione ha avuto successo, False altrimenti
        """
        self._connect()

        try:
            # Query per eliminare l'utente
            query = "DELETE FROM user_accounts WHERE id = ?"

            # Esegui la query
            self.cursor.execute(query, (user_id,))
            self.conn.commit()

            # Verifica se è stato eliminato qualcosa
            return self.cursor.rowcount > 0

        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Error deleting user {user_id}: {str(e)}")
            raise
        finally:
            self._disconnect()

    # Aggiungi un metodo per inizializzare il database separatamente
    def init_db(self):
        """
        Inizializza il database creando tutte le tabelle necessarie.

        Returns:
            True se l'inizializzazione ha successo, False altrimenti
        """
        try:
            self._initialize_db()
            return True
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            return False