"""
Network Check Module for the ABSC Audit System.

Implements specific checks related to network inventory
and device security.
"""

from typing import Dict, Any, List
from absc_audit.network.scanner import NetworkScanner
from absc_audit.checks.base import BaseCheck
from absc_audit.storage.models import Target
import logging

class NetworkInventoryCheck(BaseCheck):
    """
    Check for network device inventory and discovery.
    Implements ABSC checks related to inventory (ABSC 1.x).
    """

    def __init__(self, logger=None):
        """
        Initialize network inventory check.

        Args:
            logger: Custom logger (optional)
        """
        super().__init__(logger)
        self.network_scanner = NetworkScanner(logger=logger)

    def run(self, target: Target, params: Dict = None) -> Dict[str, Any]:
        """
        Execute network inventory check.

        Args:
            target: Target to run the check on
            params: Additional parameters (optional)

        Returns:
            Dictionary with check results
        """
        result = self._initialize_result()
        params = params or {}

        try:
            # Configurable parameters
            network_range = params.get('network_range', target.network_range)
            scan_method = params.get('scan_method', 'nmap')

            # Perform network scan
            if scan_method == 'scapy':
                devices = self.network_scanner.scan_network_scapy(network_range)
            else:
                devices = self.network_scanner.scan_network_nmap(network_range)

            # Result evaluation
            result['devices_count'] = len(devices)
            result['devices'] = devices

            # Compliance logic
            if len(devices) > 0:
                result['status'] = 'Yes complete'
                result['score'] = 100
            else:
                result['status'] = 'No'
                result['score'] = 0

            # Additional details
            result['details'] = {
                'network_range': network_range,
                'scan_method': scan_method,
                'discovered_devices': [
                    {
                        'ip': device.get('ip', 'N/A'),
                        'mac': device.get('mac', 'N/A'),
                        'hostname': device.get('hostname', 'N/A')
                    } for device in devices
                ]
            }

        except Exception as e:
            self.log_error(target, e)
            result['status'] = 'ERROR'
            result['score'] = 0
            result['error_details'] = str(e)

        return result

class NetworkSecurityCheck(BaseCheck):
    """
    Network security check.
    Performs in-depth security assessments and identifies potential vulnerabilities.
    """

    def __init__(self, logger=None):
        """
        Initialize network security check.

        Args:
            logger: Custom logger (optional)
        """
        super().__init__(logger)
        self.network_scanner = NetworkScanner(logger=logger)

    def run(self, target: Target, params: Dict = None) -> Dict[str, Any]:
        """
        Execute network security assessment.

        Args:
            target: Target to run the check on
            params: Additional parameters (optional)

        Returns:
            Dictionary with check results
        """
        result = self._initialize_result()
        params = params or {}

        try:
            # Configurable parameters
            network_range = params.get('network_range', target.network_range)

            # Perform network security assessment
            network_assessment = self.network_scanner.network_security_assessment(network_range)

            # Result evaluation
            result['devices_count'] = network_assessment.get('devices_count', 0)
            result['open_ports'] = network_assessment.get('open_ports_summary', {})
            result['potential_vulnerabilities'] = network_assessment.get('potential_vulnerabilities', [])

            # Scoring logic based on risks
            vulnerability_count = len(result['potential_vulnerabilities'])
            open_ports_count = len(result['open_ports'])

            # Evaluation criteria
            if vulnerability_count == 0 and open_ports_count <= 3:
                result['status'] = 'Yes complete'
                result['score'] = 100
            elif vulnerability_count <= 2 and open_ports_count <= 5:
                result['status'] = 'Yes partial'
                result['score'] = 70
            else:
                result['status'] = 'No'
                result['score'] = 0

            # Additional details
            result['details'] = {
                'network_range': network_range,
                'vulnerability_assessment': {
                    'total_vulnerabilities': vulnerability_count,
                    'open_ports': open_ports_count,
                    'high_risk_ports': [
                        v['port'] for v in result['potential_vulnerabilities']
                        if v.get('risk_level') == 'high'
                    ]
                }
            }

        except Exception as e:
            self.log_error(target, e)
            result['status'] = 'ERROR'
            result['score'] = 0
            result['error_details'] = str(e)

        return result

# Registration of checks in the registry
def register_network_checks(check_registry):
    """
    Register network checks in the check registry.

    Args:
        check_registry: Check registry
    """
    check_registry.register('network_inventory', NetworkInventoryCheck)
    check_registry.register('network_security', NetworkSecurityCheck)