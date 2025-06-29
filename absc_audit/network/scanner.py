"""
Advanced Network Scanning Module for the ABSC Audit System.

Implements network discovery, analysis, and monitoring functionality
using libraries like Scapy, Nmap, and proprietary analysis mechanisms.
"""

import logging
import ipaddress
import concurrent.futures
import socket
import subprocess
import platform
from typing import List, Dict, Optional, Union, Any

# Conditional imports to handle library absence
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

class NetworkDiscoveryError(Exception):
    """Custom exception for network discovery errors."""
    pass

class NetworkScanner:
    """
    Advanced network scanner with multi-method support.

    Provides methods for:
    - Device discovery
    - Network analysis
    - Network configuration assessment
    - Potential vulnerability detection
    """

    def __init__(self,
                 logger: Optional[logging.Logger] = None,
                 timeout: int = 5,
                 max_threads: int = 10):
        """
        Initialize the network scanner.

        Args:
            logger: Custom logger (optional)
            timeout: Timeout for network operations
            max_threads: Maximum number of threads for parallel scans
        """
        self.logger = logger or logging.getLogger('absc_audit.network_scanner')
        self.timeout = timeout
        self.max_threads = max_threads

        # Check library availability
        self.library_status = {
            'scapy': SCAPY_AVAILABLE,
            'nmap': NMAP_AVAILABLE
        }

        if not SCAPY_AVAILABLE or not NMAP_AVAILABLE:
            self.logger.warning(
                f"Network libraries partially available: "
                f"Scapy={SCAPY_AVAILABLE}, Nmap={NMAP_AVAILABLE}"
            )

    def validate_network_range(self, network_range: str) -> bool:
        """
        Validate a network range.

        Args:
            network_range: Network range in CIDR notation

        Returns:
            True if the range is valid, False otherwise
        """
        try:
            ipaddress.ip_network(network_range, strict=False)
            return True
        except ValueError:
            self.logger.error(f"Invalid network range: {network_range}")
            return False

    def ping_host(self, host: str) -> bool:
        """
        Check host reachability.

        Args:
            host: IP address or hostname

        Returns:
            True if the host responds, False otherwise
        """
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', '-W', str(self.timeout), host]

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout
            )
            return result.returncode == 0
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False

    def scan_network_scapy(self, network_range: str) -> List[Dict[str, str]]:
        """
        Scan a network using Scapy for ARP discovery.

        Args:
            network_range: IP range to scan (e.g. '192.168.1.0/24')

        Returns:
            List of discovered devices
        """
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy library not available")
            return []

        if not self.validate_network_range(network_range):
            return []

        try:
            arp_request = ARP(pdst=network_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp_request

            result = srp(packet, timeout=self.timeout, verbose=0)[0]

            devices = []
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': self._get_mac_vendor(received.hwsrc)
                })

            return devices

        except Exception as e:
            self.logger.error(f"Error during Scapy scan: {e}")
            return []

    def scan_network_nmap(self,
                           network_range: str,
                           ports: str = '22,80,443,3389',
                           scan_type: str = 'vulnerability') -> List[Dict[str, Any]]:
        """
        Scan a network using Nmap with different detail levels.

        Args:
            network_range: IP range to scan
            ports: Ports to scan
            scan_type: Scan type ('basic', 'detailed', 'vulnerability')

        Returns:
            List of discovered devices with details
        """
        if not NMAP_AVAILABLE:
            self.logger.error("Nmap library not available")
            return []

        if not self.validate_network_range(network_range):
            return []

        logging.info(f"SCANNING WITH NMAP {network_range} for {ports} ports on {scan_type} scan type {scan_type}")
        try:
            nm = nmap.PortScanner()

            # Select Nmap arguments based on scan type
            scan_arguments = {
                'basic': f'-sn -sV -p {ports}',
                'detailed': f'-sV -sC -p {ports}',
                'vulnerability': f'-sV --script vuln -p {ports}'
            }.get(scan_type, f'-sn -sV -p {ports}')

            nm.scan(hosts=network_range, arguments=scan_arguments)

            devices = []
            for host in nm.all_hosts():
                host_details = {
                    'ip': host,
                    'hostname': nm[host].hostname() or host,
                    'status': nm[host].state(),
                    'services': [],
                    'os_details': {}
                }

                # Service details
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service_details = nm[host][proto][port]
                        host_details['services'].append({
                            'port': port,
                            'state': service_details['state'],
                            'service': service_details['name'],
                            'version': service_details.get('version', 'Unknown')
                        })

                # OS detection
                if 'osmatch' in nm[host]:
                    host_details['os_details'] = {
                        'name': nm[host]['osmatch'][0]['name'] if nm[host]['osmatch'] else 'Unknown',
                        'accuracy': nm[host]['osmatch'][0]['accuracy'] if nm[host]['osmatch'] else 0
                    }

                devices.append(host_details)

            return devices

        except Exception as e:
            self.logger.error(f"Error during Nmap scan: {e}")
            return []

    def parallel_network_scan(self,
                               network_ranges: List[str],
                               scan_method: str = 'scapy') -> List[Dict[str, Any]]:
        """
        Perform parallel network scans.

        Args:
            network_ranges: List of network ranges to scan
            scan_method: Scan method ('scapy' or 'nmap')

        Returns:
            Consolidated list of discovered devices
        """
        all_devices = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Select scan method
            scan_func = (self.scan_network_scapy if scan_method == 'scapy'
                         else self.scan_network_nmap)

            # Perform parallel scans
            future_to_network = {
                executor.submit(scan_func, network): network
                for network in network_ranges
            }

            for future in concurrent.futures.as_completed(future_to_network):
                network = future_to_network[future]
                try:
                    devices = future.result()
                    all_devices.extend(devices)
                except Exception as e:
                    self.logger.error(f"Error scanning {network}: {e}")

        return all_devices

    def _get_mac_vendor(self, mac_address: str) -> str:
        """
        Retrieve the vendor of a MAC address.

        Args:
            mac_address: MAC address

        Returns:
            Vendor name (if identifiable)
        """
        # Basic implementation. In a real implementation,
        # a MAC-vendor mapping database could be used
        mac_prefix = mac_address[:8].replace(':', '').upper()

        # Example dictionary (to be expanded with a complete database)
        mac_vendors = {
            '000C29': 'VMware',
            '005056': 'VMware',
            '0050C2': 'VMware',
            '00FF7B': 'Microsoft',
            # Add other vendors
        }

        return mac_vendors.get(mac_prefix, 'Unknown')

    def network_security_assessment(self,
                                    network_range: str) -> Dict[str, Any]:
        """
        Perform a basic security assessment on a network.

        Args:
            network_range: Network range to assess

        Returns:
            Dictionary with assessment results
        """
        assessment = {
            'network_range': network_range,
            'devices_count': 0,
            'open_ports_summary': {},
            'potential_vulnerabilities': []
        }

        # Detailed Nmap scan
        devices = self.scan_network_nmap(network_range, scan_type='vulnerability')
        assessment['devices_count'] = len(devices)

        # Analysis of open ports and potential vulnerabilities
        for device in devices:
            for service in device.get('services', []):
                port = service['port']
                if service['state'] == 'open':
                    assessment['open_ports_summary'][port] = (
                        assessment['open_ports_summary'].get(port, 0) + 1
                    )

                    # Examples of vulnerability detection
                    if port in [21, 22, 23]:  # Potentially risky services
                        assessment['potential_vulnerabilities'].append({
                            'device': device['ip'],
                            'port': port,
                            'service': service['service'],
                            'risk_level': 'high'
                        })

        return assessment

