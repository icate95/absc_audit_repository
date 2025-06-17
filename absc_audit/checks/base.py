"""
Base Check - Classe base per tutti i controlli di sicurezza ABSC.

Questo modulo implementa la classe base che tutti i controlli
specifici devono estendere per garantire un'interfaccia comune.
"""

from abc import ABC, abstractmethod
import datetime
import logging
import uuid
from typing import Dict, List, Optional, Any, Union

from absc_audit.storage.models import Target
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class BaseCheck(ABC):
    """
    Classe base per tutti i controlli di sicurezza ABSC.

    Questa classe definisce l'interfaccia comune che tutti i controlli
    specifici devono implementare. Fornisce anche funzionalità di base
    come logging e gestione errori.
    """

    # Attributi di classe che devono essere definiti nelle sottoclassi
    ID = None  # ID ABSC del controllo (es. "1.1.1-1.1.4")
    NAME = None  # Nome breve del controllo
    DESCRIPTION = None  # Descrizione del controllo
    QUESTION = None  # Domanda di verifica
    POSSIBLE_ANSWERS = []  # Risposte possibili
    CATEGORY = None  # Categoria (es. "Inventory")
    PRIORITY = 3  # Priorità (1=alta, 2=media, 3=bassa)

    def __init__(self):
        """Inizializza il controllo."""
        # Valida gli attributi obbligatori
        if not self.ID:
            raise ValueError(f"Check ID not defined in {self.__class__.__name__}")
        if not self.NAME:
            raise ValueError(f"Check name not defined in {self.__class__.__name__}")
        if not self.DESCRIPTION:
            raise ValueError(f"Check description not defined in {self.__class__.__name__}")

        self.logger = logger

    @abstractmethod
    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Esegue il controllo sul target specificato.

        Args:
            target: Target su cui eseguire il controllo
            params: Parametri aggiuntivi per il controllo (opzionale)

        Returns:
            Dizionario con i risultati del controllo
        """
        pass

    def prepare_result(self) -> Dict:
        """
        Prepara un dizionario base per i risultati del controllo.

        Returns:
            Dizionario base per i risultati
        """
        return {
            'id': str(uuid.uuid4()),
            'check_id': self.ID,
            'timestamp': datetime.datetime.now().isoformat(),
            'status': None,
            'score': None,
            'details': {},
            'raw_data': {},
            'notes': ""
        }

    def validate_result(self, result: Dict) -> bool:
        """
        Valida un dizionario di risultati.

        Args:
            result: Dizionario di risultati da validare

        Returns:
            True se il risultato è valido, False altrimenti
        """
        # Verifica che i campi obbligatori siano presenti
        required_fields = ['check_id', 'timestamp', 'status']
        for field in required_fields:
            if field not in result:
                self.logger.error(f"Missing required field in result: {field}")
                return False

        # Verifica che lo stato sia tra le risposte possibili
        if result['status'] and result['status'] not in self.POSSIBLE_ANSWERS and result['status'] != "ERROR":
            self.logger.warning(
                f"Invalid status in result: {result['status']}. Expected one of: {self.POSSIBLE_ANSWERS}")
            return False

        return True

    def calculate_score(self, status: str) -> float:
        """
        Calcola il punteggio di conformità in base allo stato.

        Args:
            status: Stato del controllo

        Returns:
            Punteggio da 0 a 100
        """
        # Implementazione predefinita, può essere sovrascritta nelle sottoclassi
        if status == "ERROR":
            return 0

        if status == "No":
            return 0

        if status.startswith("Sì") or status.startswith("Si"):
            # Gestisci le varie sfumature di "Sì"
            if "completo" in status.lower() or "pieno" in status.lower():
                return 100
            elif "parziale" in status.lower():
                return 50
            else:
                return 70

        # Fallback per stati non riconosciuti
        return 0

    def log_check_start(self, target: Target):
        """
        Registra l'inizio dell'esecuzione del controllo.

        Args:
            target: Target su cui viene eseguito il controllo
        """
        self.logger.info(f"Starting check {self.ID} ({self.NAME}) on target {target.name}")

    def log_check_end(self, target: Target, status: str, duration: float):
        """
        Registra la fine dell'esecuzione del controllo.

        Args:
            target: Target su cui è stato eseguito il controllo
            status: Stato finale del controllo
            duration: Durata dell'esecuzione in secondi
        """
        self.logger.info(
            f"Completed check {self.ID} on target {target.name} "
            f"with status '{status}' in {duration:.2f} seconds"
        )

    def log_error(self, target: Target, error: Exception):
        """
        Registra un errore durante l'esecuzione del controllo.

        Args:
            target: Target su cui è stato eseguito il controllo
            error: Eccezione verificatasi
        """
        self.logger.error(
            f"Error in check {self.ID} on target {target.name}: {str(error)}",
            exc_info=True
        )

    def execute_command(self, target: Target, command: str, use_sudo: bool = False) -> Dict:
        """
        Esegue un comando sul target e ne restituisce l'output.

        Args:
            target: Target su cui eseguire il comando
            command: Comando da eseguire
            use_sudo: Se utilizzare sudo per l'esecuzione

        Returns:
            Dizionario con stdout, stderr e codice di uscita
        """
        # Questa è solo una funzionalità helper che verrà implementata dai connettori
        # specifici (SSH, WMI, ecc.) nelle sottoclassi concrete
        self.logger.debug(f"Would execute command on {target.name}: {command}")
        return {
            'stdout': "",
            'stderr': "Command execution not implemented in base class",
            'exit_code': -1
        }

    def check_file_exists(self, target: Target, path: str) -> bool:
        """
        Verifica se un file esiste sul target.

        Args:
            target: Target su cui verificare
            path: Percorso del file da verificare

        Returns:
            True se il file esiste, False altrimenti
        """
        # Implementazione di base, da sovrascrivere nelle sottoclassi concrete
        self.logger.debug(f"Would check if file exists on {target.name}: {path}")
        return False

    def read_file_content(self, target: Target, path: str) -> Optional[str]:
        """
        Legge il contenuto di un file sul target.

        Args:
            target: Target su cui leggere
            path: Percorso del file da leggere

        Returns:
            Contenuto del file o None in caso di errore
        """
        # Implementazione di base, da sovrascrivere nelle sottoclassi concrete
        self.logger.debug(f"Would read file content on {target.name}: {path}")
        return None

    def check_process_running(self, target: Target, process_name: str) -> bool:
        """
        Verifica se un processo è in esecuzione sul target.

        Args:
            target: Target su cui verificare
            process_name: Nome del processo da verificare

        Returns:
            True se il processo è in esecuzione, False altrimenti
        """
        # Implementazione di base, da sovrascrivere nelle sottoclassi concrete
        self.logger.debug(f"Would check if process is running on {target.name}: {process_name}")
        return False

    def check_service_status(self, target: Target, service_name: str) -> Dict:
        """
        Verifica lo stato di un servizio sul target.

        Args:
            target: Target su cui verificare
            service_name: Nome del servizio da verificare

        Returns:
            Dizionario con informazioni sullo stato del servizio
        """
        # Implementazione di base, da sovrascrivere nelle sottoclassi concrete
        self.logger.debug(f"Would check service status on {target.name}: {service_name}")
        return {
            'running': False,
            'enabled': False,
            'error': "Service status check not implemented in base class"
        }