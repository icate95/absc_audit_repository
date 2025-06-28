from typing import Type, Dict, Any, Optional

import typer
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from absc_audit.checks.base import BaseCheck


class CheckRegistry:
    """Predefined security check categories"""
    CATEGORIES = [
        "Inventory",
        "Authentication",
        "Vulnerability",
        "Malware Protection",
        "Admin Access",
        "Encryption",
        "Logging",
        "Backup"
    ]

    def __init__(self):
        # Dictionary to store checks
        self._checks: Dict[str, Type[BaseCheck]] = {}

    @staticmethod
    def validate_priority(priority: int) -> bool:
        """
        Validate that the priority is a correct value.

        Args:
            priority: Priority value to validate

        Returns:
            bool: True if the priority is valid
        """
        return priority in [1, 2, 3]

    def register(self, check_id: str, check_class: Type[BaseCheck]):
        """
        Register a new check in the registry.

        Args:
            check_id: Unique check identifier
            check_class: Check class to register
        """
        # Check that a check with the same ID doesn't already exist
        if check_id in self._checks:
            raise ValueError(f"A check with ID {check_id} already exists")

        # Register the check
        self._checks[check_id] = check_class

    def get_checks_by_category(self, category_prefix: str) -> Dict[str, Type[BaseCheck]]:
        """
        Return checks for a specific category.

        Args:
            category_prefix: Category prefix (e.g. '1' for Inventory)

        Returns:
            Dictionary of checks in the category
        """
        return {
            check_id: check_class
            for check_id, check_class in self._checks.items()
            if check_id.startswith(category_prefix)
        }

    def get_all_checks(self) -> Dict[str, Type[BaseCheck]]:
        """
        Return all registered checks.

        Returns:
            Dictionary of all checks
        """
        return self._checks

    def get_check_by_id(self, check_id: str) -> Optional[Type[BaseCheck]]:
        """
        Retrieve a specific check by ID.

        Args:
            check_id: Check identifier

        Returns:
            Check class if found, otherwise None
        """
        return self._checks.get(check_id)