"""
Core Engine - Il motore principale del sistema di audit ABSC.

Questo modulo implementa il motore centrale responsabile per l'esecuzione
dei controlli di sicurezza ABSC sugli endpoint target.
"""

import concurrent.futures
import datetime
import logging
import time
import uuid
from typing import Dict, List, Optional, Tuple, Union, Any

from absc_audit.checks.base import BaseCheck
from absc_audit.config.settings import Settings
from absc_audit.storage.models import AuditResult, Target
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class AuditEngine:
    """
    Core engine responsabile per l'esecuzione dei controlli di audit.

    Questa classe coordina l'esecuzione di tutti i controlli di sicurezza
    su uno o più target, raccoglie i risultati e li passa al ResultManager.
    """

    def __init__(self, settings: Optional[Settings] = None):
        """
        Inizializza l'audit engine.

        Args:
            settings: Configurazioni del sistema (opzionale).
        """
        self.settings = settings or Settings()
        self.result_manager = None  # Sarà impostato successivamente
        self._check_registry = {}  # Registro dei controlli disponibili

    def register_result_manager(self, result_manager):
        """
        Registra il result manager per l'elaborazione dei risultati.

        Args:
            result_manager: Istanza di ResultManager
        """
        self.result_manager = result_manager

    def register_check(self, check_id: str, check_class: type):
        """
        Registra un controllo nel sistema.

        Args:
            check_id: Identificativo ABSC del controllo
            check_class: Classe che implementa il controllo
        """
        # logger.info(f"Registering check {check_id}")
        self._check_registry[check_id] = check_class

    def get_available_checks(self) -> Dict[str, type]:
        """
        Restituisce tutti i controlli disponibili.

        Returns:
            Dizionario con ID dei controlli e relative classi
        """
        return self._check_registry

    def run_check(self,
                  check_id: str,
                  target: Target,
                  params: Optional[Dict] = None) -> AuditResult:
        """
        Esegue un singolo controllo su un target.

        Args:
            check_id: Identificativo ABSC del controllo
            target: Target su cui eseguire il controllo
            params: Parametri aggiuntivi per il controllo (opzionale)

        Returns:
            Risultato dell'audit

        Raises:
            ValueError: Se il controllo non è disponibile
        """
        if check_id not in self._check_registry:
            raise ValueError(f"Check not found: {check_id}")

        logger.info(f"Running check {check_id} on target {target.name}")

        # Crea un'istanza del controllo
        check_class = self._check_registry[check_id]
        check_instance = check_class()

        # Prepara il risultato base
        result = AuditResult(
            id=str(uuid.uuid4()),
            check_id=check_id,
            target_id=target.id,
            timestamp=datetime.datetime.now(),
            status=None,
            score=0,
            details={},
            raw_data={}
        )

        try:
            # Esegui il controllo
            check_result = check_instance.run(target, params or {})

            # Aggiorna il risultato
            result.status = check_result.get('status')
            result.score = check_result.get('score', 0)
            result.details = check_result.get('details', {})
            result.raw_data = check_result.get('raw_data', {})

            # Gestisci eventuali note o commenti
            result.notes = check_result.get('notes', '')

            logger.info(f"Check {check_id} completed with status: {result.status}")

        except Exception as e:
            logger.error(f"Error executing check {check_id}: {str(e)}", exc_info=True)
            result.status = "ERROR"
            result.details = {"error": str(e)}
            result.score = 0

        # Passa il risultato al result manager
        if self.result_manager:
            self.result_manager.process_result(result)

        return result

    def run_checks(self,
                   target: Target,
                   check_ids: Optional[List[str]] = None,
                   params: Optional[Dict] = None,
                   parallel: bool = False) -> List[AuditResult]:
        """
        Esegue una serie di controlli su un target.

        Args:
            target: Target su cui eseguire i controlli
            check_ids: Lista di controlli da eseguire (opzionale, tutti se None)
            params: Parametri aggiuntivi per i controlli (opzionale)
            parallel: Se eseguire i controlli in parallelo

        Returns:
            Lista di risultati dell'audit
        """
        results = []
        ids_to_run = check_ids or list(self._check_registry.keys())

        logger.info(f"Running {len(ids_to_run)} checks on target {target.name}")

        if parallel and self.settings.max_workers > 1:
            # Esecuzione parallela
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.settings.max_workers) as executor:
                future_to_check = {
                    executor.submit(self.run_check, check_id, target, params): check_id
                    for check_id in ids_to_run
                }

                for future in concurrent.futures.as_completed(future_to_check):
                    check_id = future_to_check[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Error in check {check_id}: {str(e)}", exc_info=True)
        else:
            # Esecuzione sequenziale
            for check_id in ids_to_run:
                try:
                    result = self.run_check(check_id, target, params)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error in check {check_id}: {str(e)}", exc_info=True)

        return results

    def run_audit(self,
                  targets: List[Target],
                  check_ids: Optional[List[str]] = None,
                  params: Optional[Dict] = None,
                  parallel_targets: bool = False,
                  parallel_checks: bool = False) -> Dict[str, List[AuditResult]]:
        """
        Esegue un audit completo su più target.

        Args:
            targets: Lista di target su cui eseguire l'audit
            check_ids: Lista di controlli da eseguire (opzionale, tutti se None)
            params: Parametri aggiuntivi per i controlli (opzionale)
            parallel_targets: Se eseguire i target in parallelo
            parallel_checks: Se eseguire i controlli in parallelo per ogni target

        Returns:
            Dizionario con target_id e lista dei risultati
        """
        audit_results = {}

        if parallel_targets and self.settings.max_workers > 1:
            # Esecuzione parallela dei target
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.settings.max_workers) as executor:
                future_to_target = {
                    executor.submit(self.run_checks, target, check_ids, params, parallel_checks): target
                    for target in targets
                }

                for future in concurrent.futures.as_completed(future_to_target):
                    target = future_to_target[future]
                    try:
                        results = future.result()
                        audit_results[target.id] = results
                    except Exception as e:
                        logger.error(f"Error in target {target.name}: {str(e)}", exc_info=True)
        else:
            # Esecuzione sequenziale dei target
            for target in targets:
                try:
                    results = self.run_checks(target, check_ids, params, parallel_checks)
                    audit_results[target.id] = results
                except Exception as e:
                    logger.error(f"Error in target {target.name}: {str(e)}", exc_info=True)

        return audit_results


class CheckRegistry:
    """
    Registro centrale dei controlli disponibili.

    Questa classe gestisce la registrazione e il recupero dei controlli
    di sicurezza implementati nel sistema.
    """

    _instance = None

    def __new__(cls):
        """Implementa il pattern Singleton."""
        if cls._instance is None:
            cls._instance = super(CheckRegistry, cls).__new__(cls)
            cls._instance._checks = {}
        return cls._instance

    def register(self, check_id: str, check_class: type):
        """
        Registra un controllo nel registro.

        Args:
            check_id: Identificativo ABSC del controllo
            check_class: Classe che implementa il controllo
        """
        if not issubclass(check_class, BaseCheck):
            raise TypeError(f"Check class must be a subclass of BaseCheck")

        self._checks[check_id] = check_class

    def get_check(self, check_id: str) -> Optional[type]:
        """
        Recupera una classe di controllo dal registro.

        Args:
            check_id: Identificativo ABSC del controllo

        Returns:
            Classe di controllo o None se non trovata
        """
        return self._checks.get(check_id)

    def get_all_checks(self) -> Dict[str, type]:
        """
        Recupera tutti i controlli registrati.

        Returns:
            Dizionario con tutti i controlli
        """
        return self._checks.copy()

    def get_checks_by_category(self, category: str) -> Dict[str, type]:
        """
        Recupera i controlli di una specifica categoria.

        Args:
            category: Categoria ABSC (es. "1" per inventario)

        Returns:
            Dizionario con i controlli della categoria
        """
        return {
            check_id: check_class
            for check_id, check_class in self._checks.items()
            if check_id.startswith(f"{category}.")
        }


class CheckFactory:
    """
    Factory per la creazione di istanze di controllo.

    Questa classe si occupa di istanziare i controlli in base all'ID ABSC.
    """

    def __init__(self, registry: Optional[CheckRegistry] = None):
        """
        Inizializza il factory.

        Args:
            registry: Registro dei controlli (opzionale)
        """
        self.registry = registry or CheckRegistry()

    def create_check(self, check_id: str) -> BaseCheck:
        """
        Crea un'istanza di controllo.

        Args:
            check_id: Identificativo ABSC del controllo

        Returns:
            Istanza del controllo

        Raises:
            ValueError: Se il controllo non è disponibile
        """
        check_class = self.registry.get_check(check_id)
        if not check_class:
            raise ValueError(f"Check not found: {check_id}")

        return check_class()

    def create_checks_by_category(self, category: str) -> List[BaseCheck]:
        """
        Crea istanze di tutti i controlli di una categoria.

        Args:
            category: Categoria ABSC (es. "1" per inventario)

        Returns:
            Lista di istanze di controllo
        """
        checks = []
        for check_id, check_class in self.registry.get_checks_by_category(category).items():
            checks.append(check_class())

        return checks