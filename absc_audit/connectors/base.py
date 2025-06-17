"""
Base Connector - Classe base per tutti i connettori di sistema.

Questo modulo implementa la classe base che tutti i connettori
specifici devono estendere per garantire un'interfaccia comune.
"""

from abc import ABC, abstractmethod
import datetime
import logging
from typing import Dict, List, Optional, Any, Union

from absc_audit.storage.models import Target
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class BaseConnector(ABC):
    """
    Classe base per tutti i connettori di sistema.

    Questa classe definisce l'interfaccia comune che tutti i connettori
    specifici devono implementare per interagire con i sistemi target.
    """

    def __init__(self, target: Target = None, **kwargs):
        """
        Inizializza il connettore.

        Args:
            target: Target su cui operare (opzionale)
            **kwargs: Parametri aggiuntivi specifici del connettore
        """
        self.target = target
        self.connection = None
        self.connected = False
        self.last_error = None
        self.logger = logger

        # Parametri di connessione
        self.params = kwargs

    @abstractmethod
    def connect(self) -> bool:
        """
        Stabilisce una connessione con il target.

        Returns:
            True se la connessione ha successo, False altrimenti
        """
        pass

    @abstractmethod
    def disconnect(self) -> bool:
        """
        Chiude la connessione con il target.

        Returns:
            True se la disconnessione ha successo, False altrimenti
        """
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """
        Verifica se la connessione è attiva.

        Returns:
            True se la connessione è attiva, False altrimenti
        """
        pass

    @abstractmethod
    def execute_command(self, command: str, timeout: int = 30, use_sudo: bool = False) -> Dict:
        """
        Esegue un comando sul target.

        Args:
            command: Comando da eseguire
            timeout: Timeout in secondi
            use_sudo: Se utilizzare sudo per l'esecuzione

        Returns:
            Dizionario con stdout, stderr e codice di uscita
        """
        pass

    @abstractmethod
    def check_file_exists(self, path: str) -> bool:
        """
        Verifica se un file esiste sul target.

        Args:
            path: Percorso del file da verificare

        Returns:
            True se il file esiste, False altrimenti
        """
        pass

    @abstractmethod
    def read_file_content(self, path: str) -> Optional[str]:
        """
        Legge il contenuto di un file sul target.

        Args:
            path: Percorso del file da leggere

        Returns:
            Contenuto del file o None in caso di errore
        """
        pass

    @abstractmethod
    def check_process_running(self, process_name: str) -> bool:
        """
        Verifica se un processo è in esecuzione sul target.

        Args:
            process_name: Nome del processo da verificare

        Returns:
            True se il processo è in esecuzione, False altrimenti
        """
        pass

    @abstractmethod
    def check_service_status(self, service_name: str) -> Dict:
        """
        Verifica lo stato di un servizio sul target.

        Args:
            service_name: Nome del servizio da verificare

        Returns:
            Dizionario con informazioni sullo stato del servizio
        """
        pass

    def log_info(self, message: str):
        """
        Registra un messaggio informativo.

        Args:
            message: Messaggio da registrare
        """
        self.logger.info(f"[{self.target.name if self.target else 'Unknown'}] {message}")

    def log_error(self, message: str, exception: Exception = None):
        """
        Registra un messaggio di errore.

        Args:
            message: Messaggio da registrare
            exception: Eccezione associata (opzionale)
        """
        self.last_error = message
        self.logger.error(
            f"[{self.target.name if self.target else 'Unknown'}] {message}",
            exc_info=bool(exception)
        )

    def log_debug(self, message: str):
        """
        Registra un messaggio di debug.

        Args:
            message: Messaggio da registrare
        """
        self.logger.debug(f"[{self.target.name if self.target else 'Unknown'}] {message}")

    def set_target(self, target: Target):
        """
        Imposta il target su cui operare.

        Args:
            target: Target su cui operare
        """
        self.target = target

    def __enter__(self):
        """
        Implementa il pattern context manager per l'utilizzo con 'with'.

        Returns:
            Istanza del connettore
        """
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Implementa il pattern context manager per l'utilizzo con 'with'.

        Args:
            exc_type: Tipo dell'eccezione
            exc_val: Valore dell'eccezione
            exc_tb: Traceback dell'eccezione
        """
        self.disconnect()