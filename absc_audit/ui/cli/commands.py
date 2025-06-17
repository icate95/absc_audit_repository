# absc_audit/ui/cli/commands.py

"""
CLI Commands - Comandi per l'interfaccia a linea di comando.

Questo modulo implementa i comandi dell'interfaccia a linea di comando (CLI)
per il sistema di audit ABSC.
"""

import argparse
import datetime
import json
import os
import sys
import time
from typing import Dict, List, Optional, Any

from absc_audit.core.engine import AuditEngine, CheckRegistry
from absc_audit.core.result_manager import ResultManager
from absc_audit.core.scheduler import Scheduler
from absc_audit.storage.models import Target, AuditResult
from absc_audit.storage.sqlite import SQLiteStorage
from absc_audit.checks.inventory import InventoryExistsCheck, DeviceDiscoveryCheck, DHCPMonitoringCheck
from absc_audit.checks.vulnerability import VulnerabilityScanCheck, PatchManagementCheck
from absc_audit.checks.malware import AntimalwareCheck, ExecutionPreventionCheck
from absc_audit.config.settings import Settings
from absc_audit.utils.logging import setup_logger
from absc_audit.storage.models import Target, AuditResult, AuditCheck
from absc_audit.checks.authentication import PasswordPolicyCheck, AdminAccountsCheck
from absc_audit.checks.admin_access import AdminAccessControlCheck, AdminRemoteAccessCheck
from absc_audit.checks.backup import BackupProcedureCheck, BackupTestingCheck
from absc_audit.checks.encryption import StorageEncryptionCheck, TransportEncryptionCheck
from absc_audit.checks.logging import LoggingConfigurationCheck, LogReviewCheck


logger = setup_logger(__name__)


class CLI:
    """
    Interfaccia a linea di comando per il sistema di audit ABSC.

    Questa classe gestisce i comandi disponibili nella CLI.
    """

    def __init__(self):
        """Inizializza la CLI."""
        self.settings = Settings()
        self.storage = SQLiteStorage(self.settings)
        self.result_manager = ResultManager(self.settings)
        self.result_manager.configure_storage(self.storage)
        self.engine = AuditEngine(self.settings)
        self.engine.register_result_manager(self.result_manager)

        # Registra i controlli disponibili
        self._register_checks()

        # Parser dei comandi
        self.parser = self._create_parser()

    def _register_checks(self):
        """Registra i controlli disponibili nel sistema."""
        registry = CheckRegistry()

        #funzione di registrazione
        registry.register(PasswordPolicyCheck.ID, PasswordPolicyCheck)
        registry.register(AdminAccountsCheck.ID, AdminAccountsCheck)

        # funzioni ci controlli admin
        registry.register(AdminAccessControlCheck.ID, AdminAccessControlCheck)
        registry.register(AdminRemoteAccessCheck.ID, AdminRemoteAccessCheck)

        # controlli backup
        registry.register(BackupProcedureCheck.ID, BackupProcedureCheck)
        registry.register(BackupTestingCheck.ID, BackupTestingCheck)

        registry.register(LoggingConfigurationCheck.ID, LoggingConfigurationCheck)
        registry.register(LogReviewCheck.ID, LogReviewCheck)

        #controlli encryptions
        registry.register(StorageEncryptionCheck.ID, StorageEncryptionCheck)
        registry.register(TransportEncryptionCheck.ID, TransportEncryptionCheck)

        # Registra i controlli dell'inventario (ABSC 1.x)
        registry.register(InventoryExistsCheck.ID, InventoryExistsCheck)
        registry.register(DeviceDiscoveryCheck.ID, DeviceDiscoveryCheck)
        registry.register(DHCPMonitoringCheck.ID, DHCPMonitoringCheck)

        # Registra i controlli delle vulnerabilità (ABSC 4.x)
        registry.register(VulnerabilityScanCheck.ID, VulnerabilityScanCheck)
        registry.register(PatchManagementCheck.ID, PatchManagementCheck)

        # Registra i controlli malware (ABSC 8.x)
        registry.register(AntimalwareCheck.ID, AntimalwareCheck)
        registry.register(ExecutionPreventionCheck.ID, ExecutionPreventionCheck)

        # Registra tutti i controlli nell'engine e nel database
        for check_id, check_class in registry.get_all_checks().items():
            self.engine.register_check(check_id, check_class)

            # Salva anche nel database
            check_instance = check_class()
            check = AuditCheck(
                id=check_id,
                name=check_instance.NAME,
                description=check_instance.DESCRIPTION,
                question=check_instance.QUESTION,
                possible_answers=check_instance.POSSIBLE_ANSWERS,
                category=check_instance.CATEGORY,
                priority=check_instance.PRIORITY,
                enabled=True
            )
            try:
                self.storage.save_check(check)
            except Exception as e:
                logger.warning(f"Errore nel salvataggio del controllo {check_id} nel database: {str(e)}")

    def _create_parser(self) -> argparse.ArgumentParser:
        """
        Crea il parser dei comandi della CLI.

        Returns:
            Parser configurato
        """
        parser = argparse.ArgumentParser(
            description="Sistema di audit per le misure minime di sicurezza ABSC",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        subparsers = parser.add_subparsers(dest="command", help="Comando da eseguire")

        # Comando: init-db
        init_db_parser = subparsers.add_parser("init-db", help="Inizializza il database")

        # Comando: list-targets
        list_targets_parser = subparsers.add_parser("list-targets", help="Elenca i target disponibili")

        # Comando: add-target
        add_target_parser = subparsers.add_parser("add-target", help="Aggiungi un nuovo target")
        add_target_parser.add_argument("--name", required=True, help="Nome del target")
        add_target_parser.add_argument("--hostname", required=True, help="Hostname o IP del target")
        add_target_parser.add_argument("--os", required=True, choices=["windows", "linux"],
                                       help="Sistema operativo del target")
        add_target_parser.add_argument("--description", help="Descrizione del target")
        add_target_parser.add_argument("--group", help="Gruppo del target")
        add_target_parser.add_argument("--tags", help="Tag del target (separati da virgola)")

        # Comando: delete-target
        delete_target_parser = subparsers.add_parser("delete-target", help="Elimina un target esistente")
        delete_target_parser.add_argument("--id", required=True, help="ID del target da eliminare")

        # Comando: list-checks
        list_checks_parser = subparsers.add_parser("list-checks", help="Elenca i controlli disponibili")
        list_checks_parser.add_argument("--category", help="Filtra per categoria")

        # Comando: run-check
        run_check_parser = subparsers.add_parser("run-check", help="Esegui un controllo specifico")
        run_check_parser.add_argument("--target", required=True, help="ID o nome del target")
        run_check_parser.add_argument("--check", required=True, help="ID del controllo da eseguire")

        # Comando: run-audit
        run_audit_parser = subparsers.add_parser("run-audit", help="Esegui un audit completo")
        run_audit_parser.add_argument("--target", required=True, help="ID o nome del target")
        run_audit_parser.add_argument("--category", help="Categoria di controlli da eseguire")
        run_audit_parser.add_argument("--priority", type=int, choices=[1, 2, 3],
                                      help="Priorità dei controlli da eseguire")
        run_audit_parser.add_argument("--parallel", action="store_true", help="Esegui i controlli in parallelo")

        # Comando: list-results
        list_results_parser = subparsers.add_parser("list-results", help="Elenca i risultati degli audit")
        list_results_parser.add_argument("--target", help="Filtra per target")
        list_results_parser.add_argument("--check", help="Filtra per controllo")
        list_results_parser.add_argument("--latest", action="store_true", help="Mostra solo i risultati più recenti")

        # Comando: generate-report
        report_parser = subparsers.add_parser("generate-report", help="Genera un report degli audit")
        report_parser.add_argument("--target", help="Filtra per target")
        report_parser.add_argument("--format", choices=["json", "csv", "html", "pdf"], default="html",
                                   help="Formato del report")
        report_parser.add_argument("--output", help="Percorso del file di output")

        return parser

    def run(self, args=None):
        """
        Esegue il comando specificato.

        Args:
            args: Argomenti della linea di comando (opzionale)
        """
        args = self.parser.parse_args(args)

        if args.command == "init-db":
            self._init_db()
        elif args.command == "list-targets":
            self._list_targets()
        elif args.command == "add-target":
            self._add_target(args)
        elif args.command == "delete-target":
            self._delete_target(args)
        elif args.command == "list-checks":
            self._list_checks(args)
        elif args.command == "run-check":
            self._run_check(args)
        elif args.command == "run-audit":
            self._run_audit(args)
        elif args.command == "list-results":
            self._list_results(args)
        elif args.command == "generate-report":
            self._generate_report(args)
        else:
            self.parser.print_help()

    def _list_targets(self):
        """Elenca i target disponibili."""
        targets = self.storage.get_all_targets()

        if not targets:
            print("Nessun target trovato.")
            return

        print(f"Target disponibili ({len(targets)}):")
        print("-" * 80)
        print(f"{'ID':<36} {'Nome':<20} {'Hostname':<20} {'OS':<10}")
        print("-" * 80)

        for target in targets:
            print(f"{target.id:<36} {target.name:<20} {target.hostname:<20} {target.os_type:<10}")

    def _add_target(self, args):
        """
        Aggiunge un nuovo target.

        Args:
            args: Argomenti del comando
        """
        # Crea il target
        target = Target(
            name=args.name,
            hostname=args.hostname,
            os_type=args.os,
            description=args.description or "",
            group=args.group or "",
            tags=args.tags.split(",") if args.tags else []
        )

        # Salva il target
        try:
            self.storage.save_target(target)
            print(f"Target aggiunto con successo (ID: {target.id}).")
        except Exception as e:
            print(f"Errore nell'aggiunta del target: {str(e)}")

    def _delete_target(self, args):
        """
        Elimina un target esistente.

        Args:
            args: Argomenti del comando
        """
        try:
            success = self.storage.delete_target(args.id)
            if success:
                print(f"Target con ID {args.id} eliminato con successo.")
            else:
                print(f"Nessun target trovato con ID {args.id}.")
        except Exception as e:
            print(f"Errore nell'eliminazione del target: {str(e)}")

    def _list_checks(self, args):
        """
        Elenca i controlli disponibili.

        Args:
            args: Argomenti del comando
        """
        checks = self.engine.get_available_checks()

        if args.category:
            checks = {
                k: v for k, v in checks.items()
                if hasattr(v, 'CATEGORY') and v.CATEGORY.lower() == args.category.lower()
            }

        if not checks:
            print("Nessun controllo trovato.")
            return

        print(f"Controlli disponibili ({len(checks)}):")
        print("-" * 100)
        print(f"{'ID':<15} {'Nome':<30} {'Categoria':<15} {'Priorità':<10}")
        print("-" * 100)

        for check_id, check_class in sorted(checks.items()):
            priority = getattr(check_class, 'PRIORITY', 3)
            category = getattr(check_class, 'CATEGORY', "")
            print(f"{check_id:<15} {check_class.NAME:<30} {category:<15} {priority:<10}")

    def _run_check(self, args):
        """
        Esegue un controllo specifico.

        Args:
            args: Argomenti del comando
        """
        # Ottieni il target
        target = self._get_target_by_id_or_name(args.target)
        if not target:
            print(f"Target non trovato: {args.target}")
            return

        # Verifica che il controllo esista
        checks = self.engine.get_available_checks()
        if args.check not in checks:
            print(f"Controllo non trovato: {args.check}")
            return

        # Assicurati che il target sia salvato nel database
        try:
            self.storage.save_target(target)
        except Exception as e:
            logger.warning(f"Errore nel salvataggio del target {target.id} nel database: {str(e)}")

        # Assicurati che il controllo sia salvato nel database
        check_class = checks[args.check]
        check_instance = check_class()
        check = AuditCheck(
            id=args.check,
            name=check_instance.NAME,
            description=check_instance.DESCRIPTION,
            question=check_instance.QUESTION,
            possible_answers=check_instance.POSSIBLE_ANSWERS,
            category=check_instance.CATEGORY,
            priority=check_instance.PRIORITY,
            enabled=True
        )
        try:
            self.storage.save_check(check)
        except Exception as e:
            logger.warning(f"Errore nel salvataggio del controllo {args.check} nel database: {str(e)}")

        print(f"Esecuzione del controllo {args.check} sul target {target.name}...")
        start_time = time.time()

        # Esegui il controllo
        try:
            result = self.engine.run_check(args.check, target)

            duration = time.time() - start_time
            print(f"Controllo completato in {duration:.2f} secondi.")
            print("-" * 80)
            print(f"Risultato: {result.status}")
            print(f"Punteggio: {result.score:.2f}")
            print(f"Note: {result.notes}")
            print("-" * 80)
            print("Dettagli:")
            for key, value in result.details.items():
                print(f"- {key}: {value}")

        except Exception as e:
            print(f"Errore nell'esecuzione del controllo: {str(e)}")

    def _run_audit(self, args):
        """
        Esegue un audit completo.

        Args:
            args: Argomenti del comando
        """
        # Ottieni il target
        target = self._get_target_by_id_or_name(args.target)
        if not target:
            print(f"Target non trovato: {args.target}")
            return

        # Filtra i controlli da eseguire
        check_ids = None
        checks = self.engine.get_available_checks()

        if args.category:
            check_ids = [
                check_id for check_id, check_class in checks.items()
                if hasattr(check_class, 'CATEGORY') and check_class.CATEGORY.lower() == args.category.lower()
            ]
        elif args.priority:
            check_ids = [
                check_id for check_id, check_class in checks.items()
                if hasattr(check_class, 'PRIORITY') and check_class.PRIORITY == args.priority
            ]

        if check_ids is not None and not check_ids:
            print("Nessun controllo trovato con i criteri specificati.")
            return

        # Numero di controlli da eseguire
        num_checks = len(check_ids) if check_ids else len(checks)

        print(f"Esecuzione di {num_checks} controlli sul target {target.name}...")
        start_time = time.time()

        # Esegui i controlli
        try:
            results = self.engine.run_checks(
                target=target,
                check_ids=check_ids,
                parallel=args.parallel
            )

            duration = time.time() - start_time
            print(f"Audit completato in {duration:.2f} secondi.")

            # Calcola statistiche
            compliant = sum(1 for r in results if r.score >= self.settings.compliance_threshold)
            non_compliant = len(results) - compliant

            print("-" * 80)
            print(f"Risultati dell'audit ({len(results)} controlli):")
            print(f"- Controlli conformi: {compliant}")
            print(f"- Controlli non conformi: {non_compliant}")
            print(f"- Tasso di conformità: {(compliant / len(results) * 100):.2f}%")
            print("-" * 80)

            # Mostra i controlli non conformi
            if non_compliant > 0:
                print("Controlli non conformi:")
                for result in sorted(results, key=lambda r: r.score):
                    if result.score < self.settings.compliance_threshold:
                        print(f"- {result.check_id}: {result.status} (Score: {result.score:.2f})")
                        print(f"  Note: {result.notes}")

        except Exception as e:
            print(f"Errore nell'esecuzione dell'audit: {str(e)}")

    def _list_results(self, args):
        """
        Elenca i risultati degli audit.

        Args:
            args: Argomenti del comando
        """
        # Filtra i risultati
        target_id = None
        if args.target:
            target = self._get_target_by_id_or_name(args.target)
            if target:
                target_id = target.id
            else:
                print(f"Target non trovato: {args.target}")
                return

        # Ottieni i risultati
        if args.latest:
            results = self.storage.get_latest_results(target_id)
        elif args.target and args.check:
            target_results = self.storage.get_results_by_target(target_id)
            results = [r for r in target_results if r.check_id == args.check]
        elif args.target:
            results = self.storage.get_results_by_target(target_id)
        elif args.check:
            results = self.storage.get_results_by_check(args.check)
        else:
            # Ottieni tutti i risultati, potrebbe essere troppi
            results = []
            for target in self.storage.get_all_targets():
                results.extend(self.storage.get_latest_results(target.id))

        if not results:
            print("Nessun risultato trovato.")
            return

        print(f"Risultati trovati ({len(results)}):")
        print("-" * 100)
        print(f"{'ID':<8} {'Target':<15} {'Check':<15} {'Timestamp':<20} {'Status':<20} {'Score':<8}")
        print("-" * 100)

        for result in sorted(results, key=lambda r: r.timestamp, reverse=True):
            target_name = self._get_target_name(result.target_id)
            timestamp = result.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"{result.id[:8]:<8} {target_name:<15} {result.check_id:<15} {timestamp:<20} {result.status:<20} {result.score:<8.2f}")

    def _generate_report(self, args):
        """
        Genera un report degli audit.

        Args:
            args: Argomenti del comando
        """
        # Filtra i risultati
        target_ids = None
        if args.target:
            target = self._get_target_by_id_or_name(args.target)
            if target:
                target_ids = [target.id]
            else:
                print(f"Target non trovato: {args.target}")
                return

        # Genera il report
        try:
            report = self.result_manager.generate_report(
                target_ids=target_ids,
                format_type=args.format
            )

            # Salva il report
            output_path = args.output
            if not output_path:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = f"audit_report_{timestamp}.{args.format}"

            with open(output_path, "w") as f:
                if args.format == "json":
                    json.dump(report, f, indent=2, default=str)
                else:
                    f.write(report)

            print(f"Report generato con successo: {output_path}")

        except Exception as e:
            print(f"Errore nella generazione del report: {str(e)}")

    def _get_target_by_id_or_name(self, id_or_name: str) -> Optional[Target]:
        """
        Ottiene un target per ID o nome.

        Args:
            id_or_name: ID o nome del target

        Returns:
            Target trovato o None
        """
        # Prova prima per ID
        target = self.storage.get_target(id_or_name)
        if target:
            return target

        # Prova per nome
        targets = self.storage.get_all_targets()
        for t in targets:
            if t.name == id_or_name:
                return t

        return None

    def _get_target_name(self, target_id: str) -> str:
        """
        Ottiene il nome di un target per ID.

        Args:
            target_id: ID del target

        Returns:
            Nome del target o ID se non trovato
        """
        target = self.storage.get_target(target_id)
        return target.name if target else target_id


    def _init_db(self):
        """Inizializza il database."""
        try:
            if self.storage.init_db():
                print("Database inizializzato con successo.")
            else:
                print("Errore nell'inizializzazione del database.")
        except Exception as e:
            print(f"Errore nell'inizializzazione del database: {str(e)}")

def main():
    """Punto di ingresso principale per la CLI."""
    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()

