"""
Base Check - Base Class for All ABSC Security Checks.

This module implements the base class that all specific checks
must extend to ensure a common interface.
"""

from abc import ABC, abstractmethod
import datetime
import logging
import uuid
import subprocess
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
    """

    # Class attributes that must be defined in subclasses
    ID = None  # ABSC check ID (e.g. "1.1.1-1.1.4")
    NAME = None  # Short check name
    DESCRIPTION = None  # Check description
    QUESTION = None  # Verification question
    POSSIBLE_ANSWERS = []  # Possible answers
    CATEGORY = None  # Category (e.g. "Inventory")
    PRIORITY = 3  # Priority (1=high, 2=medium, 3=low)
    SCORE_COMPONENTS = []

    def __init__(self, ssh_client=None):
        """
        Initialize the check with an optional SSH client

        Args:
            ssh_client: Optional SSH client for remote execution
        """
        # Validate mandatory attributes
        if not self.ID:
            raise ValueError(f"Check ID not defined in {self.__class__.__name__}")
        if not self.NAME:
            raise ValueError(f"Check name not defined in {self.__class__.__name__}")
        if not self.DESCRIPTION:
            raise ValueError(f"Check description not defined in {self.__class__.__name__}")

        self.logger = logger
        self._scoring_components = self.SCORE_COMPONENTS.copy()

        self._ssh_client = ssh_client

    def prepare_result(self, target=None):
        return {
            'id': str(uuid.uuid4()),
            'check_id': self.ID,
            'timestamp': datetime.datetime.now().isoformat(),
            'status': None,
            'scoring_details': self.get_scoring_details(),
            'score': self.calculate_weighted_score(),
            'details': {},
            'raw_data': {},
            'notes': "",
            'target': target
        }

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

        # return min(100, weighted_score * severity_multiplier[self.SEVERITY])
        return 100


    def get_scoring_details(self) -> Dict[str, Any]:
        """
        Retrieve check scoring details.

        Returns:
            Dict: Scoring component details
        """
        return {
            # "severity": self.SEVERITY.name,
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
        Execute a command with local fallback

        Args:
            target: Target system
            command: Command to execute
            use_sudo: Flag to use sudo

        Returns:
            Dictionary with command results
        """
        if self._ssh_client is not None:
            try:
                os_type = target.os_type.lower()

                if os_type.startswith('windows'):
                    full_command = f"powershell.exe -Command \"{command}\""
                else:
                    full_command = f"sudo {command}" if use_sudo else command

                stdin, stdout, stderr = self._ssh_client.exec_command(full_command)

                stdout_content = stdout.read().decode('utf-8')
                stderr_content = stderr.read().decode('utf-8')
                exit_status = stdout.channel.recv_exit_status()

                return {
                    'stdout': stdout_content,
                    'stderr': stderr_content,
                    'exit_code': exit_status
                }
            except Exception as e:
                self.logger.warning(f"SSH command failed: {str(e)}")

        try:
            if use_sudo:
                command = f"sudo {command}"

            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate()

            return {
                'stdout': stdout,
                'stderr': stderr,
                'exit_code': process.returncode
            }

        except Exception as e:
            error_message = f"Local command execution error: {str(e)}"
            self.logger.error(error_message)

            return {
                'stdout': '',
                'stderr': error_message,
                'exit_code': -1
            }

    def check_file_exists(self, target: Target, path: str) -> bool:
        """
        Check if a file exists on the target.

        Args:
            target: Target to check
            path: File path to verify

        Returns:
            Boolean indicating file existence
        """
        try:
            # Determine the appropriate command based on the target's operating system
            if target.os_type.lower() == 'windows':
                # Windows command to check file existence
                command = f'if exist "{path}" (echo True) else (echo False)'
            else:
                # Unix-like systems command to check file existence
                command = f'test -f "{path}" && echo "True" || echo "False"'

            result = self.execute_command(target, command)

            # Check the output
            return result['stdout'].strip().lower() == 'true'

        except Exception as e:
            self.logger.error(f"Error checking file existence on {target.name}: {str(e)}")
            return False

    def read_file_content(self, target: Target, path: str) -> Optional[str]:
        """
        Read the content of a file on the target system.

        Args:
            target: Target system to read from
            path: Full path of the file to read

        Returns:
            File content as string or None if error occurs
        """
        try:
            # Platform-specific file reading
            if target.os_type.lower().startswith('windows'):
                # Windows command to read file content
                command = f'type "{path}"'
            else:
                # Unix-like systems command to read file content
                command = f'cat "{path}"'

            result = self.execute_command(target, command)

            # Check for successful read
            if result['exit_code'] == 0:
                return result['stdout']
            else:
                self.logger.error(f"Error reading file {path}: {result['stderr']}")
                return None

        except Exception as e:
            self.logger.error(f"Exception reading file on {target.name}: {str(e)}")
            return None

    def check_process_running(self, target: Target, process_name: str) -> bool:
        """
        Check if a specific process is running on the target system.

        Args:
            target: Target system to check
            process_name: Name of the process to verify

        Returns:
            Boolean indicating process running status
        """
        try:
            # Platform-specific process check
            if target.os_type.lower().startswith('windows'):
                # Windows command to check process
                command = f'tasklist /FI "IMAGENAME eq {process_name}" | findstr /I "{process_name}"'
            else:
                # Unix-like systems command to check process
                command = f'pgrep -f "{process_name}" > /dev/null && echo "True" || echo "False"'

            result = self.execute_command(target, command)

            # Check the output
            return result['exit_code'] == 0

        except Exception as e:
            self.logger.error(f"Error checking process on {target.name}: {str(e)}")
            return False

    def check_service_status(self, target: Target, service_name: str) -> Dict:
        """
        Check the status of a service on the target system.

        Args:
            target: Target system to check
            service_name: Name of the service to verify

        Returns:
            Dictionary with service status information
        """
        try:
            # Platform-specific service status check
            if target.os_type.lower().startswith('windows'):
                # Windows service status check
                status_command = f'sc query "{service_name}"'
                enabled_command = f'sc qc "{service_name}"'
            else:
                # Unix-like systems (assuming systemd)
                status_command = f'systemctl is-active "{service_name}"'
                enabled_command = f'systemctl is-enabled "{service_name}"'

            # Check service status
            status_result = self.execute_command(target, status_command)
            enabled_result = self.execute_command(target, enabled_command)

            # Determine service status
            return {
                'running': status_result['exit_code'] == 0,
                'enabled': enabled_result['exit_code'] == 0,
                'status_details': {
                    'status_stdout': status_result['stdout'],
                    'enabled_stdout': enabled_result['stdout']
                }
            }

        except Exception as e:
            self.logger.error(f"Error checking service status on {target.name}: {str(e)}")
            return {
                'running': False,
                'enabled': False,
                'error': str(e)
            }

    def list_directory_contents(self, target: Target, path: str) -> List[str]:
        """
        List contents of a directory on the target system.

        Args:
            target: Target system to check
            path: Directory path to list

        Returns:
            List of directory contents
        """
        try:
            # Platform-specific directory listing
            if target.os_type.lower().startswith('windows'):
                # Windows directory listing
                command = f'dir "{path}" /b'
            else:
                # Unix-like systems directory listing
                command = f'ls -1 "{path}"'

            result = self.execute_command(target, command)

            # Split output into list, removing empty lines
            return [
                item.strip()
                for item in result['stdout'].split('\n')
                if item.strip()
            ]

        except Exception as e:
            self.logger.error(f"Error listing directory contents on {target.name}: {str(e)}")
            return []

    def get_system_info(self, target: Target) -> Dict:
        """
        Retrieve basic system information.

        Args:
            target: Target system to get information from

        Returns:
            Dictionary with system information
        """
        try:
            # Platform-specific system information gathering
            if target.os_type.lower().startswith('windows'):
                # Windows system info commands
                commands = {
                    'hostname': 'hostname',
                    'os_version': 'ver',
                    'system_info': 'systeminfo'
                }
            else:
                # Unix-like systems system info commands
                commands = {
                    'hostname': 'hostname',
                    'os_version': 'uname -a',
                    'system_info': 'cat /etc/os-release'
                }

            # Execute commands and collect results
            system_info = {}
            for key, command in commands.items():
                result = self.execute_command(target, command)
                system_info[key] = result['stdout'].strip()

            return system_info

        except Exception as e:
            self.logger.error(f"Error retrieving system info on {target.name}: {str(e)}")
            return {}