# absc_audit/core/scheduler.py

import datetime
import time
import threading
from typing import Dict, List, Optional, Any

from absc_audit.config.settings import Settings
from absc_audit.core.engine import AuditEngine
from absc_audit.storage.models import ScheduledAudit, Target
from absc_audit.storage.sqlite import SQLiteStorage
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class Scheduler:
    """
    Scheduler per l'esecuzione periodica degli audit.

    Questa classe si occupa di pianificare e gestire l'esecuzione
    automatica degli audit in base alle configurazioni.
    """

    def __init__(self, engine: AuditEngine, storage: SQLiteStorage, settings: Optional[Settings] = None):
        """
        Inizializza lo scheduler.

        Args:
            engine: Istanza dell'audit engine
            storage: Istanza del backend di storage
            settings: Configurazioni del sistema (opzionale)
        """
        self.engine = engine
        self.storage = storage
        self.settings = settings or Settings()

        self.running = False
        self.thread = None
        self.stop_event = threading.Event()

    def start(self):
        """Avvia lo scheduler."""
        if self.running:
            logger.warning("Scheduler already running")
            return

        self.running = True
        self.stop_event.clear()

        # Avvia il thread dello scheduler
        self.thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.thread.start()

        logger.info("Scheduler started")

    def stop(self):
        """Ferma lo scheduler."""
        if not self.running:
            logger.warning("Scheduler not running")
            return

        self.running = False
        self.stop_event.set()

        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5.0)

        logger.info("Scheduler stopped")

    def _scheduler_loop(self):
        """Loop principale dello scheduler."""
        logger.info("Scheduler loop started")

        while self.running and not self.stop_event.is_set():
            try:
                # Ottieni gli audit pianificati da eseguire
                scheduled_audits = self.storage.get_due_scheduled_audits()

                # Esegui gli audit
                for scheduled in scheduled_audits:
                    self._run_scheduled_audit(scheduled)

                # Attendi prima della prossima verifica
                for _ in range(60):  # Controlla ogni minuto
                    if self.stop_event.is_set():
                        break
                    time.sleep(1)

            except Exception as e:
                logger.error(f"Error in scheduler loop: {str(e)}", exc_info=True)
                time.sleep(60)  # Attendi un minuto in caso di errore

    def _run_scheduled_audit(self, scheduled: ScheduledAudit):
        """
        Esegue un audit pianificato.

        Args:
            scheduled: Audit pianificato da eseguire
        """
        logger.info(f"Running scheduled audit: {scheduled.name} (ID: {scheduled.id})")

        try:
            # Ottieni i target
            targets = []
            for target_id in scheduled.target_ids:
                target = self.storage.get_target(target_id)
                if target:
                    targets.append(target)
                else:
                    logger.warning(f"Target not found: {target_id}")

            if not targets:
                logger.error(f"No valid targets found for scheduled audit: {scheduled.id}")
                return

            # Esegui l'audit
            results = self.engine.run_audit(
                targets=targets,
                check_ids=scheduled.check_ids if scheduled.check_ids else None,
                params=scheduled.params,
                parallel_targets=True,
                parallel_checks=True
            )

            # Aggiorna i timestamp dell'audit pianificato
            scheduled.last_run = datetime.datetime.now()
            self._calculate_next_run(scheduled)

            # Salva l'audit aggiornato
            self.storage.save_scheduled_audit(scheduled)

            # Invio notifiche se configurato
            if scheduled.notify_on_completion:
                from absc_audit.core.notification import NotificationService
                notification_service = NotificationService(self.settings)

                for target_id, target_results in results.items():
                    target = next((t for t in targets if t.id == target_id), None)
                    notification_service.send_audit_summary(target_results, target)

            logger.info(f"Scheduled audit completed: {scheduled.name} (ID: {scheduled.id})")

        except Exception as e:
            logger.error(f"Error running scheduled audit {scheduled.id}: {str(e)}", exc_info=True)

    def _calculate_next_run(self, scheduled: ScheduledAudit):
        """
        Calcola il prossimo orario di esecuzione dell'audit pianificato.

        Args:
            scheduled: Audit pianificato da aggiornare
        """
        now = datetime.datetime.now()

        if scheduled.frequency == 'daily':
            # Esecuzione giornaliera
            next_run = datetime.datetime(
                now.year, now.month, now.day,
                scheduled.hour, scheduled.minute, 0
            )

            # Se l'orario è già passato, passa al giorno successivo
            if next_run <= now:
                next_run += datetime.timedelta(days=1)

        elif scheduled.frequency == 'weekly':
            # Esecuzione settimanale
            days_ahead = scheduled.day_of_week - now.weekday()
            if days_ahead <= 0:
                days_ahead += 7

            next_run = datetime.datetime(
                now.year, now.month, now.day,
                scheduled.hour, scheduled.minute, 0
            ) + datetime.timedelta(days=days_ahead)

        elif scheduled.frequency == 'monthly':
            # Esecuzione mensile
            day = min(scheduled.day_of_month,
                      [31, 29 if now.year % 4 == 0 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][now.month - 1])

            next_month = now.month + 1 if now.month < 12 else 1
            next_year = now.year if now.month < 12 else now.year + 1

            next_run = datetime.datetime(
                next_year, next_month, day,
                scheduled.hour, scheduled.minute, 0
            )

        else:
            # Frequenza non supportata, usa giornaliera
            next_run = now + datetime.timedelta(days=1)

        scheduled.next_run = next_run