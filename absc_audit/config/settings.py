"""
Settings - Configurazioni del sistema di audit ABSC.

Questo modulo contiene le configurazioni predefinite e i parametri
di funzionamento del sistema di audit.
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any


class Settings:
    """
    Configurazioni del sistema di audit ABSC.

    Questa classe contiene tutte le impostazioni necessarie
    per il funzionamento del sistema.
    """

    def __init__(self, config_file: Optional[str] = None):
        """
        Inizializza le configurazioni.

        Args:
            config_file: Percorso del file di configurazione (opzionale)
        """
        # Directory base dell'applicazione
        self.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))

        # Directory di output per report e risultati
        self.output_dir = os.path.join(self.base_dir, 'reports')

        # Configurazione database
        self.sqlite_path = os.path.join(self.base_dir, 'data', 'audit_data.db')
        self.use_postgresql = False
        self.postgresql_dsn = 'postgresql://user:password@localhost:5432/absc_audit'

        # Configurazione esecuzione
        self.max_workers = 4  # Numero massimo di worker per esecuzione parallela
        self.default_timeout = 30  # Timeout predefinito per l'esecuzione dei comandi

        # Configurazione risultati
        self.compliance_threshold = 70  # Soglia di conformità (0-100%)

        # Configurazione notifiche
        self.enable_notifications = False
        self.notification_email = 'admin@example.com'
        self.smtp_server = 'smtp.example.com'
        self.smtp_port = 587
        self.smtp_username = 'user'
        self.smtp_password = 'password'
        self.smtp_use_tls = True

        # Configurazione logging
        self.log_level = logging.INFO
        self.log_file = os.path.join(self.base_dir, 'logs', 'audit.log')
        self.log_max_size = 10 * 1024 * 1024  # 10 MB
        self.log_backup_count = 5

        # Carica configurazioni da file se specificato
        if config_file:
            self.load_from_file(config_file)

    def load_from_file(self, config_file: str):
        """
        Carica le configurazioni da un file.

        Args:
            config_file: Percorso del file di configurazione
        """
        # Implementare caricamento da file (JSON, YAML, INI, ...)
        pass

    def save_to_file(self, config_file: str):
        """
        Salva le configurazioni su un file.

        Args:
            config_file: Percorso del file di configurazione
        """
        # Implementare salvataggio su file
        pass

    def to_dict(self) -> Dict:
        """
        Converte le configurazioni in un dizionario.

        Returns:
            Dizionario con le configurazioni
        """
        # Escludi metodi e attributi privati
        return {k: v for k, v in self.__dict__.items() if not k.startswith('_') and not callable(v)}