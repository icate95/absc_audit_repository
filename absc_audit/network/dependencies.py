"""
Dependency Management and Verification for ABSC Audit Network Modules.

This module provides mechanisms to verify and manage
dependencies required for network checks.
"""

import importlib
import logging
import subprocess
import sys
from typing import Dict, List, Optional, Tuple


class NetworkDependencyManager:
    """
    Dependency manager for network checks.

    Verifies and manages libraries necessary for network functionality.
    """

    REQUIRED_LIBRARIES = [
        'scapy',
        'nmap',
        'paramiko',
        'pywinrm'
    ]

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize network dependency manager.

        Args:
            logger: Custom logger (optional)
        """
        self.logger = logger or logging.getLogger('absc_audit.network_dependencies')

    def check_library_availability(self, library_name: str) -> Tuple[bool, Optional[str]]:
        """
        Check the availability of a library.

        Args:
            library_name: Name of the library to verify

        Returns:
            Tuple (availability, version)
        """
        try:
            module = importlib.import_module(library_name)
            version = getattr(module, '__version__', 'Not detectable')
            return True, version
        except ImportError:
            return False, None

    def get_dependency_status(self) -> Dict[str, Dict[str, str]]:
        """
        Get network dependency status.

        Returns:
            Dictionary with dependency status
        """
        dependency_status = {}

        for library in self.REQUIRED_LIBRARIES:
            available, version = self.check_library_availability(library)
            dependency_status[library] = {
                'available': 'Yes' if available else 'No',
                'version': version or 'N/A'
            }

        return dependency_status

    def install_missing_dependencies(self,
                                     libraries: Optional[List[str]] = None,
                                     upgrade: bool = False) -> Dict[str, bool]:
        """
        Install missing dependencies.

        Args:
            libraries: List of libraries to install (if None, uses REQUIRED_LIBRARIES)
            upgrade: If True, upgrades existing libraries

        Returns:
            Dictionary with installation results
        """
        libraries = libraries or self.REQUIRED_LIBRARIES
        installation_results = {}

        for library in libraries:
            try:
                # Determine if library is already installed
                available, current_version = self.check_library_availability(library)

                # Construct installation command
                pip_command = [
                    sys.executable,
                    '-m', 'pip',
                    'install' if not available or upgrade else 'install',
                    f"{library}{'==latest' if upgrade else ''}"
                ]

                # Execute installation
                result = subprocess.run(
                    pip_command,
                    capture_output=True,
                    text=True
                )

                # Check result
                if result.returncode == 0:
                    self.logger.info(f"Installation/Upgrade of {library} successful")
                    installation_results[library] = True
                else:
                    self.logger.error(f"Error installing {library}: {result.stderr}")
                    installation_results[library] = False

            except Exception as e:
                self.logger.error(f"Error installing {library}: {e}")
                installation_results[library] = False

        return installation_results

    def validate_network_tools(self) -> Dict[str, bool]:
        """
        Check availability of system network tools.

        Returns:
            Dictionary with network tools status
        """
        network_tools = {
            'ping': self._check_system_tool('ping'),
            'nmap': self._check_system_tool('nmap'),
            'ssh': self._check_system_tool('ssh')
        }

        return network_tools

    def _check_system_tool(self, tool_name: str) -> bool:
        """
        Check availability of a system tool.

        Args:
            tool_name: Name of the tool to verify

        Returns:
            True if the tool is available, False otherwise
        """
        try:
            result = subprocess.run(
                ['which', tool_name],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def generate_dependency_report(self) -> str:
        """
        Generate a detailed network dependency report.

        Returns:
            Textual dependency report
        """
        report = "=== ABSC Audit - Network Dependency Report ===\n\n"

        # Library status
        report += "### Python Libraries:\n"
        dependency_status = self.get_dependency_status()
        for lib, status in dependency_status.items():
            report += f"- {lib}: {status['available']} (Version: {status['version']})\n"

        # System tools
        report += "\n### System Tools:\n"
        system_tools = self.validate_network_tools()
        for tool, available in system_tools.items():
            report += f"- {tool}: {'Available' if available else 'Not available'}\n"

        # Recommendations
        report += "\n### Recommendations:\n"
        missing_libs = [
            lib for lib, status in dependency_status.items()
            if status['available'] == 'No'
        ]
        if missing_libs:
            report += f"- Install the following missing libraries: {', '.join(missing_libs)}\n"

        missing_tools = [
            tool for tool, available in system_tools.items()
            if not available
        ]
        if missing_tools:
            report += f"- Install the following system tools: {', '.join(missing_tools)}\n"

        return report


# Initialization function for use in the system
def initialize_network_dependencies(logger=None):
    """
    Initialize and verify network dependencies.

    Args:
        logger: Custom logger (optional)

    Returns:
        Dependency manager instance
    """
    dep_manager = NetworkDependencyManager(logger)

    # Log dependency report
    if logger:
        logger.info(dep_manager.generate_dependency_report())

    return dep_manager