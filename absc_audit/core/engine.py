"""
Core Engine - The main engine of the ABSC Audit System.

This module implements the central engine responsible for executing
ABSC security checks on target endpoints.
"""

import concurrent.futures
import datetime
import uuid
from typing import Dict, List, Optional

from absc_audit.checks.base import BaseCheck
from absc_audit.config.settings import Settings
from absc_audit.storage.models import AuditResult, Target
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class AuditEngine:
    """
    Core engine responsible for executing audit checks.

    This class coordinates the execution of all security checks
    on one or more targets, collects results, and passes them to the ResultManager.
    """

    def __init__(self, settings: Optional[Settings] = None):
        """
        Initialize the audit engine.

        Args:
            settings: System configurations (optional).
        """
        self.settings = settings or Settings()
        self.result_manager = None
        self._check_registry = {}

    def register_result_manager(self, result_manager):
        """
        Register the result manager for processing results.

        Args:
            result_manager: ResultManager instance
        """
        self.result_manager = result_manager

    def register_check(self, check_id: str, check_class: type):
        """
        Register a check in the system.

        Args:
            check_id: ABSC check identifier
            check_class: Class implementing the check
        """
        # logger.info(f"Registering check {check_id}")
        self._check_registry[check_id] = check_class

    def get_available_checks(self) -> Dict[str, type]:
        """
        Returns all available checks.

        Returns:
            Dictionary with check IDs and their classes
        """
        return self._check_registry

    def run_check(self,
                  check_id: str,
                  target: Target,
                  params: Optional[Dict] = None) -> AuditResult:
        """
        Execute a single check on a target.

        Args:
            check_id: ABSC check identifier
            target: Target to run the check on
            params: Additional check parameters (optional)

        Returns:
            Audit result

        Raises:
            ValueError: If the check is not available
        """
        if check_id not in self._check_registry:
            raise ValueError(f"Check not found: {check_id}")

        # logger.info(f"Running check {check_id} on target {target.name}")

        # Create check instance
        check_class = self._check_registry[check_id]
        check_instance = check_class()

        # Prepare base result
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
            # Run the check
            check_result = check_instance.run(target, params or {})

            # Update the result
            result.status = check_result.get('status')
            result.score = check_result.get('score', 0)
            result.details = check_result.get('details', {})
            result.raw_data = check_result.get('raw_data', {})

            # Handle any notes or comments
            result.notes = check_result.get('notes', '')

            logger.info(f"Check {check_id} completed with status: {result.status}")

        except Exception as e:
            logger.error(f"Error executing check {check_id}: {str(e)}", exc_info=True)
            result.status = "ERROR"
            result.details = {"error": str(e)}
            result.score = 0

        # Pass the result to result manager
        if self.result_manager:
            self.result_manager.process_result(result)

        return result

    def run_checks(self,
                   target: Target,
                   check_ids: Optional[List[str]] = None,
                   params: Optional[Dict] = None,
                   parallel: bool = False) -> List[AuditResult]:
        """
        Execute a series of checks on a target.

        Args:
            target: Target to run checks on
            check_ids: List of checks to execute (optional, all if None)
            params: Additional check parameters (optional)
            parallel: Whether to run checks in parallel

        Returns:
            List of audit results
        """
        results = []
        ids_to_run = check_ids or list(self._check_registry.keys())

        logger.info(f"Running {len(ids_to_run)} checks on target {target.name}")

        if parallel and self.settings.max_workers > 1:
            # Parallel execution
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
            # Sequential execution
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
        Execute a complete audit on multiple targets.

        Args:
            targets: List of targets to run the audit on
            check_ids: List of checks to execute (optional, all if None)
            params: Additional check parameters (optional)
            parallel_targets: Whether to run targets in parallel
            parallel_checks: Whether to run checks in parallel for each target

        Returns:
            Dictionary with target_id and list of results
        """
        audit_results = {}

        if parallel_targets and self.settings.max_workers > 1:
            # Parallel target execution
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
            # Sequential target execution
            for target in targets:
                try:
                    results = self.run_checks(target, check_ids, params, parallel_checks)
                    audit_results[target.id] = results
                except Exception as e:
                    logger.error(f"Error in target {target.name}: {str(e)}", exc_info=True)

        return audit_results


class CheckRegistry:
    """
    Central registry of available checks.

    This class manages the registration and retrieval of security
    checks implemented in the system.
    """

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

    _instance = None

    def __new__(cls):
        """Implements the Singleton pattern."""
        if cls._instance is None:
            cls._instance = super(CheckRegistry, cls).__new__(cls)
            cls._instance._checks = {}
        return cls._instance

    def register(self, check_id: str, check_class: type):
        """
        Register a check in the registry.

        Args:
            check_id: ABSC check identifier
            check_class: Class implementing the check
        """
        if not issubclass(check_class, BaseCheck):
            raise TypeError(f"Check class must be a subclass of BaseCheck")

        self._checks[check_id] = check_class

    def get_check(self, check_id: str) -> Optional[type]:
        """
        Retrieve a check class from the registry.

        Args:
            check_id: ABSC check identifier

        Returns:
            Check class or None if not found
        """
        return self._checks.get(check_id)

    def get_all_checks(self) -> Dict[str, type]:
        """
        Retrieve all registered checks.

        Returns:
            Dictionary with all checks
        """
        return self._checks.copy()

    def get_checks_by_category(self, category: str) -> Dict[str, type]:
        """
        Retrieve checks from a specific category.

        Args:
            category: ABSC category (e.g. "1" for inventory)

        Returns:
            Dictionary with category checks
        """
        return {
            check_id: check_class
            for check_id, check_class in self._checks.items()
            if check_id.startswith(f"{category}.")
        }


class CheckFactory:
    """
    Factory for creating check instances.

    This class handles instantiating checks based on ABSC ID.
    """

    def __init__(self, registry: Optional[CheckRegistry] = None):
        """
        Initialize the factory.

        Args:
            registry: Check registry (optional)
        """
        self.registry = registry or CheckRegistry()

    def create_check(self, check_id: str) -> BaseCheck:
        """
        Create a check instance.

        Args:
            check_id: ABSC check identifier

        Returns:
            Check instance

        Raises:
            ValueError: If the check is not available
        """
        check_class = self.registry.get_check(check_id)
        if not check_class:
            raise ValueError(f"Check not found: {check_id}")

        return check_class()

    def create_checks_by_category(self, category: str) -> List[BaseCheck]:
        """
        Create instances of all checks in a category.

        Args:
            category: ABSC category (e.g. "1" for inventory)

        Returns:
            List of check instances
        """
        checks = []
        for check_id, check_class in self.registry.get_checks_by_category(category).items():
            checks.append(check_class())

        return checks