"""
Web Utilities - Utilities for the web interface.

This module provides utility functions for the Flask web interface.
"""

from absc_audit.core.engine import AuditEngine, CheckRegistry
from absc_audit.storage.sqlite import SQLiteStorage
from absc_audit.storage.models import AuditCheck, Target
from absc_audit.checks.inventory import InventoryExistsCheck, DeviceDiscoveryCheck, DHCPMonitoringCheck
from absc_audit.checks.network_inventory_additional_check import NetworkInventoryAdditionalCheck
from absc_audit.checks.vulnerability import VulnerabilityScanCheck, PatchManagementCheck
from absc_audit.checks.malware import AntimalwareCheck, ExecutionPreventionCheck
from absc_audit.checks.authentication import PasswordPolicyCheck, AdminAccountsCheck
from absc_audit.checks.admin_access import AdminAccessControlCheck, AdminRemoteAccessCheck
from absc_audit.checks.backup import BackupProcedureCheck, BackupTestingCheck
from absc_audit.checks.encryption import StorageEncryptionCheck, TransportEncryptionCheck
from absc_audit.checks.logging import LoggingConfigurationCheck, LogReviewCheck


def init_registry(engine: AuditEngine, storage: SQLiteStorage):
    """
    Initialize the audit log.

    Args:
        engine: Engine instance
        storage: Storage instance
    """
    registry = CheckRegistry()

    # Record inventory controls (ABSC 1.x)
    registry.register(InventoryExistsCheck.ID, InventoryExistsCheck)
    registry.register(DeviceDiscoveryCheck.ID, DeviceDiscoveryCheck)
    registry.register(DHCPMonitoringCheck.ID, DHCPMonitoringCheck)

    # Record inventory controls advanced (ABSC 1.x)
    registry.register(NetworkInventoryAdditionalCheck.ID, NetworkInventoryAdditionalCheck)

    # Record authentication checks (ABSC 2.x)
    registry.register(PasswordPolicyCheck.ID, PasswordPolicyCheck)
    registry.register(AdminAccountsCheck.ID, AdminAccountsCheck)

    # Record encryption checks (ABSC 3.x)
    registry.register(StorageEncryptionCheck.ID, StorageEncryptionCheck)
    registry.register(TransportEncryptionCheck.ID, TransportEncryptionCheck)

    # Record vulnerability checks (ABSC 4.x)
    registry.register(VulnerabilityScanCheck.ID, VulnerabilityScanCheck)
    registry.register(PatchManagementCheck.ID, PatchManagementCheck)

    # Record administrative access controls (ABSC 5.x)
    registry.register(AdminAccessControlCheck.ID, AdminAccessControlCheck)
    registry.register(AdminRemoteAccessCheck.ID, AdminRemoteAccessCheck)

    # Record backup checks (ABSC 13.x)
    registry.register(BackupProcedureCheck.ID, BackupProcedureCheck)
    registry.register(BackupTestingCheck.ID, BackupTestingCheck)

    # Record logging controls (ABSC 10.x)
    registry.register(LoggingConfigurationCheck.ID, LoggingConfigurationCheck)
    registry.register(LogReviewCheck.ID, LogReviewCheck)

    # Record malware checks (ABSC 8.x)
    registry.register(AntimalwareCheck.ID, AntimalwareCheck)
    registry.register(ExecutionPreventionCheck.ID, ExecutionPreventionCheck)

    # Log all checks in the engine
    for check_id, check_class in registry.get_all_checks().items():
        engine.register_check(check_id, check_class)

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
            print(f"Error saving control {check_id} to database: {str(e)}")

def format_score(score: float) -> str:
    """
    Formats a score as a percentage.

    Args:
        score: Score to format

    Returns:
        Score formatted as a percentage
    """
    return f"{score:.2f}%"


def format_timestamp(timestamp) -> str:
    """
    Formats a timestamp into readable format.

    Args:
        timestamp: Timestamp to format

    Returns:
        Formatted timestamp
    """
    if isinstance(timestamp, str):
        # Assume ISO format
        from datetime import datetime
        timestamp = datetime.fromisoformat(timestamp)

    return timestamp.strftime("%d/%m/%Y %H:%M:%S")


def status_to_badge_class(status: str) -> str:
    """
    Converts a state to a CSS class for badges.

    Args:
        status: State to convert

    Returns:
        CSS class for badge
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
    Converts a score to a CSS class for progress bars.

    Args:
        score: Score to convert
        threshold: Conformance threshold

    Returns:
        CSS class for progress bar
    """
    if score >= threshold:
        return "bg-success"
    elif score >= threshold * 0.7:
        return "bg-warning"
    else:
        return "bg-danger"