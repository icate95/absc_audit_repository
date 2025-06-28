"""
Base Check - Base Class for All ABSC Security Checks.

This module implements the base class that all specific checks
must extend to ensure a common interface.
"""

from abc import ABC, abstractmethod
import datetime
import logging
import uuid
from enum import Enum
from typing import Dict, List, Optional, Any, Union

from absc_audit.storage.models import Target
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)

class SeverityLevel(Enum):
    """Security check severity levels"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

class ScoreComponent:
    """
    Scoring component for a security check.

    Represents a specific sub-aspect of a check,
    with its own weight and score.
    """
    def __init__(
        self,
        name: str,
        weight: float,
        score: float = 0.0,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize a scoring component.

        Args:
            name: Component name
            weight: Component weight (0.0 - 1.0)
            score: Component score (0.0 - 100.0)
            details: Additional component details
        """
        self.name = name
        self.weight = weight
        self.score = score
        self.details = details or {}

class BaseCheck(ABC):
    """
    Base class for all ABSC security checks with advanced scoring system.

    This class defines the common interface that all specific checks
    must implement. It also provides basic functionality like
    logging and error handling.
    # Attributes
    ID = None
    NAME = None
    DESCRIPTION = None
    QUESTION = None
    POSSIBLE_ANSWERS = []
    CATEGORY = None
    PRIORITY = 3
    SEVERITY: SeverityLevel = SeverityLevel.MEDIUM
    SCORE_COMPONENTS: List[ScoreComponent] = []
    """

    # Class attributes that must be defined in subclasses
    ID = None  # ABSC check ID (e.g. "1.1.1-1.1.4")
    NAME = None  # Short check name
    DESCRIPTION = None  # Check description
    QUESTION = None  # Verification question
    POSSIBLE_ANSWERS = []  # Possible answers
    CATEGORY = None  # Category (e.g. "Inventory")
    PRIORITY = 3  # Priority (1=high, 2=medium, 3=low)

    def __init__(self):
        """Initialize the check."""
        # Validate mandatory attributes
        if not self.ID:
            raise ValueError(f"Check ID not defined in {self.__class__.__name__}")
        if not self.NAME:
            raise ValueError(f"Check name not defined in {self.__class__.__name__}")
        if not self.DESCRIPTION:
            raise ValueError(f"Check description not defined in {self.__class__.__name__}")

        self.logger = logger
        self._scoring_components = self.SCORE_COMPONENTS.copy()

    def add_score_component(
        self,
        name: str,
        weight: float,
        score: float = 0.0,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Add a scoring component to the check.

        Args:
            name: Component name
            weight: Component weight
            score: Component score
            details: Additional details
        """
        component = ScoreComponent(name, weight, score, details)
        self._scoring_components.append(component)

    def calculate_weighted_score(self) -> float:
        """
        Calculate weighted score considering components and severity.

        Returns:
            float: Final check score
        """
        if not self._scoring_components:
            return 0.0

        # Calculate average component score
        component_scores = [
            comp.score * comp.weight
            for comp in self._scoring_components
        ]

        # Severity multiplier
        severity_multiplier = {
            SeverityLevel.CRITICAL: 1.5,
            SeverityLevel.HIGH: 1.3,
            SeverityLevel.MEDIUM: 1.0,
            SeverityLevel.LOW: 0.8
        }

        # Calculate final score
        weighted_score = sum(component_scores) / sum(
            comp.weight for comp in self._scoring_components
        )

        return min(100, weighted_score * severity_multiplier[self.SEVERITY])

    def get_scoring_details(self) -> Dict[str, Any]:
        """
        Retrieve check scoring details.

        Returns:
            Dict: Scoring component details
        """
        return {
            "severity": self.SEVERITY.name,
            "components": [
                {
                    "name": comp.name,
                    "weight": comp.weight,
                    "score": comp.score,
                    "details": comp.details
                } for comp in self._scoring_components
            ],
            "weighted_score": self.calculate_weighted_score()
        }

    @abstractmethod
    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Execute the check on the specified target.

        Args:
            target: Target to run the check on
            params: Additional check parameters (optional)

        Returns:
            Dictionary with check results
        """
        pass

    def prepare_result(self) -> Dict:
        """
        Prepare a base dictionary for check results.

        Returns:
            Base dictionary for results
        """
        result = super().prepare_result()

        return {
            'id': str(uuid.uuid4()),
            'check_id': self.ID,
            'timestamp': datetime.datetime.now().isoformat(),
            'status': None,
            'scoring_details': self.get_scoring_details(),
            'score': self.calculate_weighted_score(),
            'details': {},
            'raw_data': {},
            'notes': ""
        }

    def validate_result(self, result: Dict) -> bool:
        """
        Validate a result dictionary.

        Args:
            result: Result dictionary to validate

        Returns:
            True if the result is valid, False otherwise
        """
        # Check that mandatory fields are present
        required_fields = ['check_id', 'timestamp', 'status']
        for field in required_fields:
            if field not in result:
                self.logger.error(f"Missing required field in result: {field}")
                return False

        # Verify that status is among possible answers
        if result['status'] and result['status'] not in self.POSSIBLE_ANSWERS and result['status'] != "ERROR":
            self.logger.warning(
                f"Invalid status in result: {result['status']}. Expected one of: {self.POSSIBLE_ANSWERS}")
            return False

        return True

    def calculate_score(self, status: str) -> float:
        """
        Calculate compliance score based on status.

        Args:
            status: Check status

        Returns:
            Score from 0 to 100
        """
        # Default implementation, can be overridden in subclasses
        if status == "ERROR":
            return 0

        if status == "No":
            return 0

        if status.startswith("Sì") or status.startswith("Si"):
            # Handle various "Yes" nuances
            if "completo" in status.lower() or "pieno" in status.lower():
                return 100
            elif "parziale" in status.lower():
                return 50
            else:
                return 70

        # Fallback for unrecognized statuses
        return 0

    def log_check_start(self, target: Target):
        """
        Log the start of check execution.

        Args:
            target: Target being checked
        """
        self.logger.info(f"Starting check {self.ID} ({self.NAME}) on target {target.name}")

    def log_check_end(self, target: Target, status: str, duration: float):
        """
        Log the end of check execution.

        Args:
            target: Target that was checked
            status: Final check status
            duration: Execution duration in seconds
        """
        self.logger.info(
            f"Completed check {self.ID} on target {target.name} "
            f"with status '{status}' in {duration:.2f} seconds"
        )

    def log_error(self, target: Target, error: Exception):
        """
        Log an error during check execution.

        Args:
            target: Target being checked
            error: Exception that occurred
        """
        self.logger.error(
            f"Error in check {self.ID} on target {target.name}: {str(error)}",
            exc_info=True
        )

    def execute_command(self, target: Target, command: str, use_sudo: bool = False) -> Dict:
        """
        Execute a command on the target and return its output.

        Args:
            target: Target to execute command on
            command: Command to execute
            use_sudo: Whether to use sudo for execution

        Returns:
            Dictionary with stdout, stderr, and exit code
        """
        # This is only a helper functionality that will be implemented by
        # specific connectors (SSH, WMI, etc.) in concrete subclasses
        self.logger.debug(f"Would execute command on {target.name}: {command}")
        return {
            'stdout': "",
            'stderr': "Command execution not implemented in base class",
            'exit_code': -1
        }

    def check_file_exists(self, target: Target, path: str) -> bool:
        """
        Check if a file exists on the target.

        Args:
            target: Target to check
            path: File path to verify

        Returns:
            True if the file exists, False otherwise
        """
        # Basic implementation, to be overridden in concrete subclasses
        self.logger.debug(f"Would check if file exists on {target.name}: {path}")
        return False

    def read_file_content(self, target: Target, path: str) -> Optional[str]:
        """
        Read file content on the target.

        Args:
            target: Target to read from
            path: File path to read

        Returns:
            File content or None in case of error
        """
        # Basic implementation, to be overridden in concrete subclasses
        self.logger.debug(f"Would read file content on {target.name}: {path}")
        return None

    def check_process_running(self, target: Target, process_name: str) -> bool:
        """
        Check if a process is running on the target.

        Args:
            target: Target to check
            process_name: Process name to verify

        Returns:
            True if the process is running, False otherwise
        """
        # Basic implementation, to be overridden in concrete subclasses
        self.logger.debug(f"Would check if process is running on {target.name}: {process_name}")
        return False

    def check_service_status(self, target: Target, service_name: str) -> Dict:
        """
        Check the status of a service on the target.

        Args:
            target: Target to check
            service_name: Service name to verify

        Returns:
            Dictionary with service status information
        """
        # Basic implementation, to be overridden in concrete subclasses
        self.logger.debug(f"Would check service status on {target.name}: {service_name}")
        return {
            'running': False,
            'enabled': False,
            'error': "Service status check not implemented in base class"
        }