# absc_audit/ui/web/utils.py

"""
Web Utilities - Utilità per l'interfaccia web.

Questo modulo fornisce funzioni di utilità per l'interfaccia web Flask.
"""

import os
import json
from absc_audit.core.engine import AuditEngine, CheckRegistry
from absc_audit.storage.sqlite import SQLiteStorage
from absc_audit.storage.models import AuditCheck, Target
from absc_audit.checks.inventory import InventoryExistsCheck, DeviceDiscoveryCheck, DHCPMonitoringCheck
from absc_audit.checks.vulnerability import VulnerabilityScanCheck, PatchManagementCheck
from absc_audit.checks.malware import AntimalwareCheck, ExecutionPreventionCheck
from absc_audit.checks.authentication import PasswordPolicyCheck, AdminAccountsCheck
from absc_audit.checks.admin_access import AdminAccessControlCheck, AdminRemoteAccessCheck
from absc_audit.checks.backup import BackupProcedureCheck, BackupTestingCheck
from absc_audit.checks.encryption import StorageEncryptionCheck, TransportEncryptionCheck
from absc_audit.checks.logging import LoggingConfigurationCheck, LogReviewCheck


def init_registry(engine: AuditEngine, storage: SQLiteStorage):
    """
    Inizializza il registro dei controlli.

    Args:
        engine: Istanza dell'engine
        storage: Istanza dello storage
    """
    registry = CheckRegistry()

    # Registra i controlli dell'autenticazione (ABSC 2.x)
    registry.register(PasswordPolicyCheck.ID, PasswordPolicyCheck)
    registry.register(AdminAccountsCheck.ID, AdminAccountsCheck)

    # Registra i controlli dell'accesso amministrativo (ABSC 5.x)
    registry.register(AdminAccessControlCheck.ID, AdminAccessControlCheck)
    registry.register(AdminRemoteAccessCheck.ID, AdminRemoteAccessCheck)

    # Registra i controlli del backup (ABSC 13.x)
    registry.register(BackupProcedureCheck.ID, BackupProcedureCheck)
    registry.register(BackupTestingCheck.ID, BackupTestingCheck)

    # Registra i controlli del logging (ABSC 10.x)
    registry.register(LoggingConfigurationCheck.ID, LoggingConfigurationCheck)
    registry.register(LogReviewCheck.ID, LogReviewCheck)

    # Registra i controlli della cifratura (ABSC 3.x)
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

    # Registra tutti i controlli nell'engine
    for check_id, check_class in registry.get_all_checks().items():
        engine.register_check(check_id, check_class)

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
            storage.save_check(check)
        except Exception as e:
            print(f"Errore nel salvataggio del controllo {check_id} nel database: {str(e)}")


def load_sample_data(storage: SQLiteStorage):
    """
    Carica dati di esempio nello storage.

    Args:
        storage: Istanza dello storage
    """
    # Crea alcuni target di esempio se non ce ne sono
    if len(storage.get_all_targets()) == 0:
        example_targets = [
            Target(
                name="Windows Server 2019",
                hostname="win-srv-01",
                ip_address="192.168.1.10",
                os_type="windows",
                os_version="Windows Server 2019",
                description="Server principale Windows",
                group="Servers",
                tags=["windows", "server", "production"]
            ),
            Target(
                name="Ubuntu Server 20.04",
                hostname="ubuntu-srv-01",
                ip_address="192.168.1.20",
                os_type="linux",
                os_version="Ubuntu 20.04 LTS",
                description="Server principale Linux",
                group="Servers",
                tags=["linux", "server", "production"]
            ),
            Target(
                name="Windows 10 Client",
                hostname="win10-client-01",
                ip_address="192.168.1.100",
                os_type="windows",
                os_version="Windows 10 Enterprise",
                description="PC client Windows",
                group="Clients",
                tags=["windows", "client", "workstation"]
            )
        ]

        for target in example_targets:
            try:
                storage.save_target(target)
                print(f"Target di esempio '{target.name}' aggiunto con successo")
            except Exception as e:
                print(f"Errore nell'aggiunta del target di esempio '{target.name}': {str(e)}")


def format_score(score: float) -> str:
    """
    Formatta un punteggio come percentuale.

    Args:
        score: Punteggio da formattare

    Returns:
        Punteggio formattato come percentuale
    """
    return f"{score:.2f}%"


def format_timestamp(timestamp) -> str:
    """
    Formatta un timestamp in formato leggibile.

    Args:
        timestamp: Timestamp da formattare

    Returns:
        Timestamp formattato
    """
    if isinstance(timestamp, str):
        # Assume ISO format
        from datetime import datetime
        timestamp = datetime.fromisoformat(timestamp)

    return timestamp.strftime("%d/%m/%Y %H:%M:%S")


def status_to_badge_class(status: str) -> str:
    """
    Converte uno stato in una classe CSS per i badge.

    Args:
        status: Stato da convertire

    Returns:
        Classe CSS per il badge
    """
    if not status:
        return "badge-secondary"

    status_lower = status.lower()

    if "si completo" in status_lower or "sì completo" in status_lower:
        return "badge-success"
    elif status_lower.startswith("si") or status_lower.startswith("sì"):
        return "badge-primary"
    elif status_lower == "no":
        return "badge-danger"
    elif "error" in status_lower:
        return "badge-warning"
    else:
        return "badge-secondary"


def score_to_progress_class(score: float, threshold: float = 70.0) -> str:
    """
    Converte un punteggio in una classe CSS per le progress bar.

    Args:
        score: Punteggio da convertire
        threshold: Soglia di conformità

    Returns:
        Classe CSS per la progress bar
    """
    if score >= threshold:
        return "bg-success"
    elif score >= threshold * 0.7:
        return "bg-warning"
    else:
        return "bg-danger"