"""
Inventory Check - Implementation of ABSC 1.x Inventory Checks.

This module implements checks related to device inventory
according to ABSC 1.x specifications.
"""
import logging
import time
import re
import os
import json
import socket
import subprocess
import datetime

from typing import Dict, List, Optional, Any, Tuple

from absc_audit.checks.base import BaseCheck
from absc_audit.storage.models import Target
from absc_audit.utils.network import scan_network, parse_network_discovery


class InventoryExistsCheck(BaseCheck):
    """
    Check to verify inventory existence (ABSC 1.1.1-1.1.4).

    Verifies if an active resource inventory exists on the network.
    """

    ID = "1.1.1-1.1.4"
    NAME = "Active Resource Inventory"
    DESCRIPTION = "Network device inventory management with automatic discovery and traffic analysis mechanisms"
    QUESTION = "Does an active resource inventory exist on the network?"
    POSSIBLE_ANSWERS = ["Yes", "Yes with automatic update", "No"]
    CATEGORY = "Inventory"
    PRIORITY = 1  # High priority

    # Common inventory file paths
    INVENTORY_COMMON_PATHS = [
        "/var/lib/device-inventory.json",
        "/var/lib/inventory/devices.json",
        "/etc/inventory/network-devices.csv",
        "C:\\ProgramData\\IT\\inventory.json",
        "C:\\ProgramData\\Inventory\\devices.xml",
    ]

    # Common inventory management tools
    INVENTORY_TOOLS = [
        # Linux
        {"name": "ocs-inventory", "process": "ocs-agent", "service": "ocsinventory-agent"},
        {"name": "glpi-agent", "process": "glpi-agent", "service": "glpi-agent"},
        {"name": "snmpd", "process": "snmpd", "service": "snmpd"},
        # Windows
        {"name": "OCS Inventory Agent", "process": "OCSInventory.exe", "service": "OCS_AGENT_SERVICE"},
        {"name": "GLPI Agent", "process": "GLPI-Agent.exe", "service": "GLPI-AGENT"},
    ]

    def prepare_result(self, target=None):
        """
        Override prepare_result method to add specific details
        """
        base_result = super().prepare_result(target)

        # Add specific details and status
        base_result['details'] = self.get_specific_details()
        base_result['status'] = self.determine_status()

        # Calculate score based on status
        base_result['score'] = self.calculate_score_from_status(base_result['status'])

        return base_result

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Execute the check on the specified target.

        Args:
            target: Target to run the check on
            params: Additional check parameters (optional)

        Returns:
            Dictionary with check results
        """
        params = params or {}
        start_time = time.time()
        result = self.prepare_result()

        try:
            # 1. Verifica file di inventario comuni
            inventory_files = self._check_common_inventory_files(target)

            # 2. Controlla software di gestione asset
            asset_tools = self._check_asset_management_tools(target)

            # 3. Esegui discovery di rete per confronto
            discovered_devices = self._perform_network_discovery(target, params)

            # 4. Determina se l'inventario è aggiornato automaticamente
            auto_update = self._check_auto_update_mechanisms(target)

            #1. Arp table
            arp_table = self._get_arp_table(target)

            # 2. Arricchisci i dati ARP
            enriched_table = self._enrich_arp_data(arp_table)

            # 3. Salva l'inventario
            inventory_path = self._save_inventory(enriched_table, target)

            # Compila i risultati
            result['raw_data'] = {
                'inventory_files': inventory_files,
                'asset_tools': asset_tools,
                'discovered_devices': len(discovered_devices),
                'auto_update_mechanism': auto_update,
                'total_devices': len(enriched_table),
                'inventory_path': inventory_path,
                'devices': enriched_table
            }

            # Determine status
            if inventory_files or asset_tools:
                if auto_update:
                    result['status'] = "Yes with automatic update"
                else:
                    result['status'] = "Yes"
            else:
                result['status'] = "No"

            # Calculate score
            result['score'] = self.calculate_score(result['status'])

            # Add details
            result['details'] = {
                'found_inventory': bool(inventory_files or asset_tools),
                'auto_updated': auto_update,
                'inventory_files': [f['path'] for f in inventory_files],
                'inventory_tools': [t['name'] for t in asset_tools],
                'coverage': self._calculate_coverage(discovered_devices, inventory_files, asset_tools)
            }

            # Add notes
            if result['status'] == "No":
                result['notes'] = "No network resource inventory was found. It is necessary to implement an inventory system."
            elif result['status'] == "Yes":
                result['notes'] = "An inventory is present, but lacks an automatic update mechanism. It is recommended to implement an automatic discovery solution."
            else:
                result['notes'] = "Inventory present with automatic update mechanism."

        except Exception as e:
            self.log_error(target, e)
            result['status'] = "ERROR"
            result['details'] = {'error': str(e)}
            result['score'] = 0
        finally:
            duration = time.time() - start_time
            self.log_check_end(target, result['status'], duration)

        return result

    def _check_common_inventory_files(self, target: Target) -> List[Dict]:
        """
        Check for common inventory files.

        Args:
            target: Target to check

        Returns:
            List of dictionaries with information about found files
        """
        self.logger.debug(f"Checking common inventory files on {target.name}")
        found_files = []

        for path in self.INVENTORY_COMMON_PATHS:
            if self.check_file_exists(target, path):
                self.logger.info(f"Found inventory file on {target.name}: {path}")

                last_modified = self._get_file_last_modified(target, path)

                file_format = self._determine_file_format(path)

                found_files.append({
                    'path': path,
                    'last_modified': last_modified,
                    'format': file_format
                })

        org_paths = self._get_organization_inventory_paths(target)
        for path in org_paths:
            if self.check_file_exists(target, path):
                self.logger.info(f"Found organization-specific inventory file on {target.name}: {path}")

                last_modified = self._get_file_last_modified(target, path)

                file_format = self._determine_file_format(path)

                found_files.append({
                    'path': path,
                    'last_modified': last_modified,
                    'format': file_format
                })

        return found_files

    def _check_asset_management_tools(self, target: Target) -> List[Dict]:
        """
        Check for inventory management tools.

        Args:
            target: Target to check

        Returns:
            List of dictionaries with information about the tools found
        """
        self.logger.debug(f"Checking asset management tools on {target.name}")
        found_tools = []

        for tool in self.INVENTORY_TOOLS:
            # Controlla se il processo è in esecuzione
            process_running = self.check_process_running(target, tool['process'])

            # Controlla lo stato del servizio
            service_status = self.check_service_status(target, tool['service'])

            if process_running or service_status.get('running', False):
                self.logger.info(f"Found inventory tool on {target.name}: {tool['name']}")
                found_tools.append({
                    'name': tool['name'],
                    'process_running': process_running,
                    'service_running': service_status.get('running', False),
                    'service_enabled': service_status.get('enabled', False)
                })

        return found_tools

    def _perform_network_discovery(self, target: Target, params: Dict) -> List[Dict]:
        """
        Performs a network discovery to find active devices.

        Args:
            target: Target to perform discovery
            params: Additional parameters

        Returns:
            List of dictionaries with information about the devices found
        """
        #todo implementare network discovery qui
        # Questa funzione potrebbe eseguire una scansione di rete utilizzando
        # nmap o altre utilità. Per semplicità, qui restituiamo dati di esempio.
        # In un'implementazione reale, questo utilizzerebbe il modulo network.
        self.logger.debug(f"Would perform network discovery from {target.name}")

        # Nella versione reale:
        # network_range = params.get('network_range', '192.168.1.0/24')
        # return scan_network(target, network_range)

        # Dati di esempio per scopi dimostrativi
        # return [
        #     {'ip': '192.168.1.1', 'mac': '00:11:22:33:44:55', 'hostname': 'gateway.local', 'type': 'router'},
        #     {'ip': '192.168.1.10', 'mac': '00:11:22:33:44:56', 'hostname': 'server01.local', 'type': 'server'},
        #     {'ip': '192.168.1.11', 'mac': '00:11:22:33:44:57', 'hostname': 'server02.local', 'type': 'server'},
        #     {'ip': '192.168.1.100', 'mac': '00:11:22:33:44:58', 'hostname': 'pc01.local', 'type': 'workstation'},
        #     {'ip': '192.168.1.101', 'mac': '00:11:22:33:44:59', 'hostname': 'pc02.local', 'type': 'workstation'},
        # ]
        return []

    def _check_auto_update_mechanisms(self, target: Target) -> bool:
        """
        Check if there are any automatic inventory update mechanisms.

        Args:
            target: Target to check

        Returns:
            True if there are automatic inventory update mechanisms
        """
        self.logger.debug(f"Checking auto-update mechanisms on {target.name}")

        # Controlla la presenza di cron job o attività pianificate
        has_scheduled_task = self._check_scheduled_tasks(target)

        # Controlla la presenza di servizi di auto-discovery
        has_discovery_service = self._check_discovery_services(target)

        # Verifica se gli strumenti di gestione dell'inventario trovati supportano l'aggiornamento automatico
        # OCS Inventory e GLPI Agent supportano l'aggiornamento automatico per default
        has_auto_update_tool = False
        for tool in self.INVENTORY_TOOLS:
            if (self.check_process_running(target, tool['process']) or
                    self.check_service_status(target, tool['service']).get('running', False)):
                if tool['name'] in ['ocs-inventory', 'glpi-agent', 'OCS Inventory Agent', 'GLPI Agent']:
                    has_auto_update_tool = True
                    break

        return has_scheduled_task or has_discovery_service or has_auto_update_tool

    def _check_scheduled_tasks(self, target: Target) -> bool:
        """
        Check for scheduled tasks to update inventory.

        Args:
            target: Target to check

        Returns:
            True if there are scheduled tasks for inventory
        """
        # Su Linux, controlla i job cron
        if target.os_type.lower() in ['linux', 'unix']:
            # Cerca nei file crontab
            cron_paths = ['/etc/crontab', '/var/spool/cron/crontabs/root']
            for path in cron_paths:
                content = self.read_file_content(target, path)
                if content and re.search(r'inventory|asset|device.*discovery', content, re.IGNORECASE):
                    return True

        # Su Windows, controlla le attività pianificate
        elif target.os_type.lower() == 'windows':
            # Esegui il comando schtasks
            result = self.execute_command(target,
                                          'schtasks /query /fo LIST /v | findstr /i "inventory asset discovery"')
            if result['exit_code'] == 0 and result['stdout']:
                return True

        return False

    def _check_discovery_services(self, target: Target) -> bool:
        """
        Check for automatic discovery services.

        Args:
            target: Target to check

        Returns:
            True if automatic discovery services exist
        """
        discovery_services = [
            'avahi-daemon',  # Linux mDNS
            'llmnrd',  # Linux LLMNR
            'netbios-ns',  # NetBIOS Name Service
            'lldpd',  # LLDP daemon
            'snmp-trap',  # SNMP trap receiver
            'dnssrv',  # Windows DNS Service
            'Browser',  # Computer Browser Service (Windows)
            'lltdsvc'  # Link-Layer Topology Discovery (Windows)
        ]

        for service in discovery_services:
            status = self.check_service_status(target, service)
            if status.get('running', False):
                return True

        return False

    def _calculate_coverage(self, discovered_devices: List[Dict], inventory_files: List[Dict],
                            asset_tools: List[Dict]) -> float:
        """
        Calculates the inventory coverage over the network.

        Args:
            discovered_devices: Devices discovered by discovery
            inventory_files: Inventory files found
            asset_tools: Inventory management tools found

        Returns:
            Coverage percentage (0-100)
        """
        # This is a simplified implementation
        # In a real system, you would read the inventory files and compare them with the discovery results

        if not discovered_devices:
            return 0

        # If there are active asset management tools, we assume good coverage
        if asset_tools:
            return 90.0

        # If there are inventory files, we assume medium coverage
        if inventory_files:
            now = time.time()
            max_age_days = 30 # Consider a file older than 30 days old

            for file_info in inventory_files:
                last_modified = file_info.get('last_modified', 0)
                age_days = (now - last_modified) / (60 * 60 * 24)

                if age_days <= max_age_days:
                    return 70.0

            return 40.0

        return 0

    def _get_file_last_modified(self, target: Target, path: str) -> float:
        """
        Gets the last modified date of a file.

        Args:
            target: Target to check
            path: Path to the file

        Returns:
            Last modified timestamp or 0 on error
        """
        # In a real implementation, this function would use the appropriate
        # connector to get the last modification date of the file

        # For now, let's return a recent timestamp to simulate
        return time.time() - (3 * 24 * 60 * 60)  # 3 days ago

    def _determine_file_format(self, path: str) -> str:
        """
        Determines the format of an inventory file based on its extension.

        Args:
            path: File path

        Returns:
            File format (json, xml, csv, txt, unknown)
        """
        ext = os.path.splitext(path)[1].lower()

        if ext == '.json':
            return 'json'
        elif ext == '.xml':
            return 'xml'
        elif ext == '.csv':
            return 'csv'
        elif ext == '.txt':
            return 'txt'
        else:
            return 'unknown'

    def _get_organization_inventory_paths(self, target: Target) -> List[str]:
        """
        Gets organization-specific paths for inventory files.

        Args:
            target: Target to check

        Returns:
            List of potential paths
        """
        # In a real implementation, this function might
        # look up a configuration or query the system
        # to find organization-specific paths

        # Let's return some additional common paths
        if target.os_type.lower() in ['linux', 'unix']:
            return [
                '/opt/inventory/devices.json',
                '/usr/local/share/inventory/network.csv',
                '/home/admin/network-inventory.json'
            ]
        elif target.os_type.lower() == 'windows':
            return [
                'C:\\IT\\NetworkInventory.xlsx',
                'D:\\Inventory\\network-devices.json',
                'C:\\Users\\Administrator\\Documents\\IT\\inventory.csv'
            ]
        else:
            return []

    def get_specific_details(self):
        """
        Collects specific details for inventory control
        """
        details = {}
        try:
            inventory_items = self.get_inventory_items()

            details = {
                'total_items': len(inventory_items),
                'item_types': self.categorize_items(inventory_items),
                'last_updated': self.get_last_inventory_update(),
                'missing_critical_items': self.find_missing_critical_items(inventory_items)
            }
        except Exception as e:
            details = {
                'error': str(e),
                'error_type': type(e).__name__
            }

        return details

    def determine_status(self):
        """
        Determines the status of the check based on the details collected
        """
        details = self.get_specific_details()

        if 'error' in details:
            return 'error'

        if details.get('total_items', 0) == 0:
            return 'critical'

        if details.get('missing_critical_items'):
            return 'warning'

        return 'compliant'

    def get_inventory_items(self):
        """
        Method to retrieve inventory items
        This is just an example - you should implement specific logic
        to retrieve items from your system
        """
        # Example of item retrieval (adapt to your context)
        try:
            # Here you could have a query to a database,
            # an API, a configuration file, etc.
            items = [
                {'name': 'Laptop', 'type': 'hardware', 'serial': 'SN12345'},
                {'name': 'Server', 'type': 'hardware', 'serial': 'SN67890'},
                # other...
            ]
            return items
        except Exception as e:
            print(f"Errore nel recupero degli elementi dell'inventario: {e}")
            return []
    def categorize_items(self, items):
        """
        Categorize inventory items by type
        """
        categories = {}
        for item in items:
            item_type = item.get('type', 'unknown')
            categories[item_type] = categories.get(item_type, 0) + 1
        return categories

    def get_last_inventory_update(self):
        """
        Retrieve the date of the last inventory update
        """
        try:
            # Example - you could retrieve this from a database, log file, etc.
            return datetime.datetime.now().isoformat()
        except Exception:
            return None

    def find_missing_critical_items(self, items):
        """
        Identify missing critical items
        """
        # Define critical items that must always be present
        critical_items = ['Laptop', 'Server']

        missing_items = [
            item for item in critical_items
            if not any(item.lower() in inv_item['name'].lower() for inv_item in items)
        ]

        return missing_items

    def calculate_score_from_status(self, status):
        """
        Calculates a score based on the control status
        """
        score_map = {
            'compliant': 100,
            'warning': 50,
            'critical': 0,
            'error': 0
        }
        return score_map.get(status, 0)

    def _get_arp_table(self, target: Target) -> List[Dict[str, str]]:
        """
        Retrieve ARP table for the target system.

        Args:
            target: Target object to determine operating system

        Returns:
            List of dictionaries with device information
        """
        arp_table = []

        try:
            if target.os_type.lower() == 'linux':
                # Command for Linux
                arp_output = self._run_shell_command(['arp', '-e'])
            elif target.os_type.lower() == 'windows':
                # Command for Windows
                arp_output = self._run_shell_command(['arp', '-a'])
            else:
                self.logger.warning(f"Unsupported operating system: {target.os_type}")
                return []

            if not arp_output:
                return []

            # ARP output parsing
            for line in arp_output.splitlines()[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 3:
                    arp_entry = {
                        'ip': parts[0],
                        'mac': parts[2],
                        'type': parts[-1] if len(parts) > 3 else 'unknown'
                    }
                    arp_table.append(arp_entry)

        except Exception as e:
            self.logger.error(f"Error retrieving ARP table: {e}")

        return arp_table

    def _enrich_arp_data(self, arp_table: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Enrich ARP data with additional information.

        Args:
            arp_table: Base ARP table

        Returns:
            ARP table enriched with hostname
        """
        enriched_table = []
        for entry in arp_table:
            enriched_entry = entry.copy()
            enriched_entry['hostname'] = self._resolve_hostname(entry['ip'])
            enriched_table.append(enriched_entry)
        return enriched_table

    def _save_inventory(self, inventory: List[Dict[str, str]], target: Target) -> str:
        """
        Save inventory to a JSON file.

        Args:
            inventory: List of devices
            target: Target object to determine path

        Returns:
            Path of the saved file
        """
        try:
            # Determine save path
            if target.os_type.lower() == 'linux':
                inventory_dir = '/var/log/absc_audit/inventory'
            else:
                inventory_dir = 'C:\\ProgramData\\ABSC_Audit\\Inventory'

            # Create directory if it doesn't exist
            import os
            os.makedirs(inventory_dir, exist_ok=True)

            # Filename with timestamp
            filename = f"network_inventory_{int(time.time())}.json"
            full_path = os.path.join(inventory_dir, filename)

            # Save inventory
            with open(full_path, 'w') as f:
                json.dump(inventory, f, indent=2)

            return full_path

        except Exception as e:
            self.logger.error(f"Error saving inventory: {e}")
            return "Unknown"

    def _run_shell_command(self, command: List[str]) -> Optional[str]:
        """
        Execute a shell command safely.

        Args:
            command: List of command arguments

        Returns:
            Command output or None in case of error
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            self.logger.error(f"Error executing command: {e}")
            return None


class DeviceDiscoveryCheck(BaseCheck):
    """
    Check to verify device detection system implementation (ABSC 1.1.3-1.1.4).

    Verifies if a device detection system is implemented with alarm generation for anomalies.
    """

    ID = "1.1.3-1.1.4"
    NAME = "Network Device Detection"
    DESCRIPTION = "Device detection and traffic analysis with alarm generation"
    QUESTION = "Is a device detection system implemented with alarm generation for anomalies?"
    POSSIBLE_ANSWERS = ["Yes with traffic analysis", "Yes with discovery", "Yes with alarms", "Yes complete", "No"]
    CATEGORY = "Inventory"
    PRIORITY = 1  # High priority

    # Common device detection tools
    DISCOVERY_TOOLS = [
        # Linux
        {"name": "Nagios", "process": "nagios", "service": "nagios"},
        {"name": "Zabbix", "process": "zabbix_server", "service": "zabbix-server"},
        {"name": "Snort", "process": "snort", "service": "snort"},
        {"name": "Suricata", "process": "suricata", "service": "suricata"},
        {"name": "arpwatch", "process": "arpwatch", "service": "arpwatch"},
        # Windows
        {"name": "PRTG", "process": "PRTGCore", "service": "PRTGCoreService"},
        {"name": "Solarwinds", "process": "NPM", "service": "SolarWinds"},
        {"name": "Wireshark", "process": "Wireshark", "service": None},
    ]

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Execute the check on device detection system implementation.

        Args:
            target: Target to run the check on
            params: Additional check parameters (optional)

        Returns:
            Dictionary with check results
        """
        params = params or {}
        start_time = time.time()
        result = self.prepare_result()

        try:
            self.log_check_start(target)

            # 1. Check for discovery tools
            discovery_tools = self._check_discovery_tools(target)

            # 2. Check traffic analysis capability
            traffic_analysis = self._check_traffic_analysis(target)

            # 3. Check alarm generation
            alarm_capability = self._check_alarm_capability(target)

            # Compile results
            result['raw_data'] = {
                'discovery_tools': discovery_tools,
                'traffic_analysis': traffic_analysis,
                'alarm_capability': alarm_capability
            }

            # Determine status
            if discovery_tools and traffic_analysis and alarm_capability:
                result['status'] = "Yes complete"
            elif discovery_tools and traffic_analysis:
                result['status'] = "Yes with traffic analysis"
            elif discovery_tools and alarm_capability:
                result['status'] = "Yes with alarms"
            elif discovery_tools:
                result['status'] = "Yes with discovery"
            else:
                result['status'] = "No"

            # Calculate score
            result['score'] = self._calculate_custom_score(result['status'])

            # Add details
            result['details'] = {
                'has_discovery_tools': bool(discovery_tools),
                'has_traffic_analysis': traffic_analysis,
                'has_alarm_capability': alarm_capability,
                'discovery_tools': [t['name'] for t in discovery_tools],
            }

            # Add notes
            if result['status'] == "No":
                result['notes'] = "No device detection system was found. It is necessary to implement a solution."
            elif result['status'] == "Yes with discovery":
                result['notes'] = "A discovery system is present, but lacks traffic analysis and alarm generation capabilities."
            elif result['status'] == "Yes with alarms":
                result['notes'] = "A discovery system with alarms is present, but traffic analysis is missing."
            elif result['status'] == "Yes with traffic analysis":
                result['notes'] = "A discovery system with traffic analysis is present, but alarm generation is missing."
            else:
                result['notes'] = "Complete system with discovery, traffic analysis, and alarm generation."

        except Exception as e:
            self.log_error(target, e)
            result['status'] = "ERROR"
            result['details'] = {'error': str(e)}
            result['score'] = 0
        finally:
            duration = time.time() - start_time
            self.log_check_end(target, result['status'], duration)

        return result

    def _check_discovery_tools(self, target: Target) -> List[Dict]:
        """
        Check for device detection tools.

        Args:
            target: Target to check

        Returns:
            List of dictionaries with tool information
        """
        self.logger.debug(f"Checking discovery tools on {target.name}")
        found_tools = []

        for tool in self.DISCOVERY_TOOLS:
            # Check if the process is running
            process_running = self.check_process_running(target, tool['process'])

            # Check service status
            service_status = {"running": False, "enabled": False}
            if tool['service']:
                service_status = self.check_service_status(target, tool['service'])

            if process_running or service_status.get('running', False):
                self.logger.info(f"Found discovery tool on {target.name}: {tool['name']}")
                found_tools.append({
                    'name': tool['name'],
                    'process_running': process_running,
                    'service_running': service_status.get('running', False),
                    'service_enabled': service_status.get('enabled', False)
                })

        return found_tools

    def _check_traffic_analysis(self, target: Target) -> bool:
        """
        Check if the system can analyze network traffic.

        Args:
            target: Target to check

        Returns:
            True if a traffic analysis system is present
        """
        self.logger.debug(f"Checking traffic analysis capability on {target.name}")

        # Check for specific traffic analysis tools
        traffic_analysis_tools = [
            "snort", "suricata", "wireshark", "ntopng", "zeek", "argus", "tcpdump",
            "netflow", "sflow", "ipfix", "packetbeat", "moloch", "nprobe"
        ]

        for tool in traffic_analysis_tools:
            if self.check_process_running(target, tool):
                self.logger.info(f"Found traffic analysis tool on {target.name}: {tool}")
                return True

        # Check configuration files of previously found discovery tools
        for tool in self.DISCOVERY_TOOLS:
            if tool['name'] == "Nagios":
                # Check Nagios configuration for traffic monitoring
                config_path = "/etc/nagios/nrpe.d/traffic.cfg"
                if self.check_file_exists(target, config_path):
                    return True
            elif tool['name'] == "Zabbix":
                # Check Zabbix configuration for traffic monitoring
                config_path = "/etc/zabbix/zabbix_agentd.d/traffic.conf"
                if self.check_file_exists(target, config_path):
                    return True
            elif tool['name'] == "PRTG":
                # PRTG includes traffic sensors by default
                return True

        return False

    def _check_alarm_capability(self, target: Target) -> bool:
        """
        Check if the system can generate alarms for new devices or anomalies.

        Args:
            target: Target to check

        Returns:
            True if an alarm generation system is present
        """
        self.logger.debug(f"Checking alarm capability on {target.name}")

        # Check for log files containing alarms
        alarm_log_paths = [
            "/var/log/alerts.log",
            "/var/log/security/alerts.log",
            "/var/log/intrusion/",
            "/var/log/nagios/alerts.log",
            "/var/log/zabbix/zabbix_alerter.log",
            "C:\\Program Files\\PRTG Network Monitor\\Logs\\Alerts",
            "C:\\Program Files\\Nagios\\var\\alerts.log"
        ]

        for path in alarm_log_paths:
            if self.check_file_exists(target, path):
                self.logger.info(f"Found alarm log on {target.name}: {path}")
                return True

        # Check alert services
        alert_services = ["nagios-alerter", "zabbix-alerter", "snort-alert", "alertmanager"]
        for service in alert_services:
            status = self.check_service_status(target, service)
            if status.get('running', False):
                self.logger.info(f"Found alert service on {target.name}: {service}")
                return True

        # Check monitoring tools that support alarms by default
        for tool in self.DISCOVERY_TOOLS:
            if tool['name'] in ["Nagios", "Zabbix", "PRTG", "Solarwinds"]:
                # These tools support alarms by default
                if self.check_process_running(target, tool['process']) or self.check_service_status(target, tool['service']).get('running', False):
                    return True

        return False

    def _calculate_custom_score(self, status: str) -> float:
        """
        Calculate a custom score based on the status.

        Args:
            status: Check status

        Returns:
            Score from 0 to 100
        """
        if status == "Yes complete":
            return 100
        elif status == "Yes with traffic analysis":
            return 80
        elif status == "Yes with alarms":
            return 70
        elif status == "Yes with discovery":
            return 50
        elif status == "No":
            return 0
        else:
            return 0


class DHCPMonitoringCheck(BaseCheck):
    """
    Check to verify DHCP log monitoring (ABSC 1.2.1-1.2.2).

    Verifies if DHCP server logs are monitored and used to improve inventory.
    """

    ID = "1.2.1-1.2.2"
    NAME = "DHCP Log Monitoring"
    DESCRIPTION = "DHCP log monitoring and analysis to improve inventory"
    QUESTION = "Are DHCP server logs monitored and used to improve inventory?"
    POSSIBLE_ANSWERS = ["Yes", "No"]
    CATEGORY = "Inventory"
    PRIORITY = 2  # Medium priority

    # Common paths for DHCP logs
    DHCP_LOG_PATHS = [
        # Linux
        "/var/log/dhcpd.log",
        "/var/log/dhcp/dhcpd.log",
        "/var/log/messages",
        "/var/log/syslog",
        # Windows
        "C:\\Windows\\System32\\dhcp\\DhcpSrvLog*.log",
        "C:\\Windows\\System32\\LogFiles\\DHCP",
    ]

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Execute the DHCP log monitoring check.

        Args:
            target: Target to run the check on
            params: Additional check parameters (optional)

        Returns:
            Dictionary with check results
        """
        params = params or {}
        start_time = time.time()
        result = self.prepare_result()

        try:
            self.log_check_start(target)

            # 1. Check for DHCP logs
            dhcp_logs = self._check_dhcp_logs(target)

            # 2. Check for log analysis scripts or procedures
            analysis_scripts = self._check_analysis_scripts(target)

            # 3. Check inventory integration
            inventory_integration = self._check_inventory_integration(target)

            # Compile results
            result['raw_data'] = {
                'dhcp_logs': dhcp_logs,
                'analysis_scripts': analysis_scripts,
                'inventory_integration': inventory_integration
            }

            # Determine status
            if dhcp_logs and (analysis_scripts or inventory_integration):
                result['status'] = "Yes"
            else:
                result['status'] = "No"

            # Calculate score
            result['score'] = self.calculate_score(result['status'])

            # Add details
            result['details'] = {
                'has_dhcp_logs': bool(dhcp_logs),
                'has_analysis_scripts': bool(analysis_scripts),
                'has_inventory_integration': inventory_integration,
                'dhcp_log_paths': [log['path'] for log in dhcp_logs],
                'analysis_script_paths': [script['path'] for script in analysis_scripts]
            }

            # Add notes
            if result['status'] == "No":
                if dhcp_logs:
                    result['notes'] = "DHCP logs are present but not analyzed or used to update the inventory."
                else:
                    result['notes'] = "No DHCP logs were found on the system. Verify that the DHCP server is configured for logging."
            else:
                result['notes'] = "DHCP logs are monitored and used to improve the inventory."

        except Exception as e:
            self.log_error(target, e)
            result['status'] = "ERROR"
            result['details'] = {'error': str(e)}
            result['score'] = 0
        finally:
            duration = time.time() - start_time
            self.log_check_end(target, result['status'], duration)

        return result

    def _check_dhcp_logs(self, target: Target) -> List[Dict]:
        """
        Check for DHCP logs on the target.

        Args:
            target: Target to check

        Returns:
            List of dictionaries with log information
        """
        self.logger.debug(f"Checking DHCP logs on {target.name}")
        found_logs = []

        # Check common paths
        for path in self.DHCP_LOG_PATHS:
            if self.check_file_exists(target, path):
                self.logger.info(f"Found DHCP log on {target.name}: {path}")

                # Read file modification date
                last_modified = self._get_file_last_modified(target, path)

                # Check if the file has been modified recently (last 24 hours)
                is_active = (time.time() - last_modified) < (24 * 60 * 60)

                # Add to information
                found_logs.append({
                    'path': path,
                    'last_modified': last_modified,
                    'is_active': is_active
                })

        # Check DHCP server configuration for logging
        dhcp_config_paths = [
            "/etc/dhcp/dhcpd.conf",
            "/etc/dhcpd.conf",
            "C:\\Windows\\System32\\dhcp\\dhcpd.conf",
        ]

        for path in dhcp_config_paths:
            content = self.read_file_content(target, path)
            if content and re.search(r'log-facility|logging', content, re.IGNORECASE):
                self.logger.info(f"Found DHCP logging configuration on {target.name}: {path}")

        return found_logs

    def _check_analysis_scripts(self, target: Target) -> List[Dict]:
        """
        Check for scripts or procedures to analyze DHCP logs.

        Args:
            target: Target to check

        Returns:
            List of dictionaries with script information
        """
        self.logger.debug(f"Checking DHCP log analysis scripts on {target.name}")
        found_scripts = []

        # Check for common scripts for DHCP log analysis
        script_paths = [
            "/usr/local/bin/dhcp-analyze.py",
            "/usr/local/bin/dhcp-to-inventory.py",
            "/usr/local/bin/dhcp-monitor.sh",
            "/etc/cron.daily/dhcp-inventory-update",
            "/opt/scripts/dhcp-analysis.py",
            "C:\\Scripts\\DHCPAnalysis.ps1",
            "C:\\Scripts\\UpdateInventoryFromDHCP.ps1",
        ]

        for path in script_paths:
            if self.check_file_exists(target, path):
                self.logger.info(f"Found DHCP analysis script on {target.name}: {path}")

                # Read file modification date
                last_executed = self._get_file_last_modified(target, path)

                # Determine if recently executed (last 7 days)
                recently_executed = (time.time() - last_executed) < (7 * 24 * 60 * 60)

                # Add to information
                found_scripts.append({
                    'path': path,
                    'last_executed': last_executed,
                    'recently_executed': recently_executed
                })

        # Check cron/scheduled tasks
        if target.os_type.lower() in ['linux', 'unix']:
            # Search in crontab files
            cron_paths = ['/etc/crontab', '/var/spool/cron/crontabs/root']
            for path in cron_paths:
                content = self.read_file_content(target, path)
                if content and re.search(r'dhcp.*log|dhcp.*inventory', content, re.IGNORECASE):
                    self.logger.info(f"Found DHCP analysis cron job on {target.name}: {path}")
                    found_scripts.append({
                        'path': path,
                        'type': 'cron',
                        'recently_executed': True  # Assume it is executed regularly
                    })

        elif target.os_type.lower() == 'windows':
            # Run schtasks command
            result = self.execute_command(target, 'schtasks /query /fo LIST /v | findstr /i "dhcp"')
            if result['exit_code'] == 0 and result['stdout']:
                self.logger.info(f"Found DHCP analysis scheduled task on {target.name}")
                found_scripts.append({
                    'path': 'Windows Scheduled Task',
                    'type': 'scheduled_task',
                    'recently_executed': True  # Assume it is executed regularly
                })

        return found_scripts

    def _check_inventory_integration(self, target: Target) -> bool:
        """
        Check if DHCP logs are integrated with the inventory.

        Args:
            target: Target to check

        Returns:
            True if there is integration between DHCP and inventory
        """
        self.logger.debug(f"Checking DHCP integration with inventory on {target.name}")

        # Check for configuration files linking DHCP and inventory
        integration_paths = [
            "/etc/dhcp-to-inventory.conf",
            "/etc/inventory/sources/dhcp.conf",
            "/opt/inventory/config/dhcp-integration.json",
            "C:\\ProgramData\\Inventory\\dhcp-config.json",
        ]

        for path in integration_paths:
            if self.check_file_exists(target, path):
                self.logger.info(f"Found DHCP-inventory integration config on {target.name}: {path}")
                return True

        # Check for specific integration scripts
        script_paths = [
            "/usr/local/bin/dhcp-to-inventory.py",
            "/usr/local/bin/sync-dhcp-inventory.sh",
            "C:\\Scripts\\SyncDHCPToInventory.ps1",
        ]

        for path in script_paths:
            if self.check_file_exists(target, path):
                self.logger.info(f"Found DHCP-inventory integration script on {target.name}: {path}")
                return True

        return False

    def _get_file_last_modified(self, target: Target, path: str) -> float:
        """
        Get the last modification date of a file.

        Args:
            target: Target to check
            path: File path

        Returns:
            Timestamp of the last modification or 0 in case of error
        """
        # In a real implementation, this function would use the appropriate connector
        # to obtain the last modification date of the file

        # For now, return a recent timestamp to simulate
        return time.time() - (2 * 24 * 60 * 60)  # 2 days ago