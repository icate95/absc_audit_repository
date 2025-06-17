"""
Inventory Check - Implementazione dei controlli di inventario ABSC 1.x.

Questo modulo implementa i controlli relativi all'inventario dei dispositivi
secondo le specifiche ABSC 1.x.
"""

import time
import re
import os
import json
from typing import Dict, List, Optional, Any, Tuple

from absc_audit.checks.base import BaseCheck
from absc_audit.storage.models import Target
from absc_audit.utils.network import scan_network, parse_network_discovery


class InventoryExistsCheck(BaseCheck):
    """
    Controllo per verificare l'esistenza di un inventario (ABSC 1.1.1-1.1.4).

    Verifica se esiste un inventario delle risorse attive sulla rete.
    """

    ID = "1.1.1-1.1.4"
    NAME = "Inventario delle risorse attive"
    DESCRIPTION = "Gestione inventario dispositivi di rete con meccanismi di scoperta automatica e analisi del traffico"
    QUESTION = "Esiste un inventario delle risorse attive sulla rete?"
    POSSIBLE_ANSWERS = ["Sì", "Sì con aggiornamento automatico", "No"]
    CATEGORY = "Inventory"
    PRIORITY = 1  # Alta priorità

    # Percorsi comuni per i file di inventario
    INVENTORY_COMMON_PATHS = [
        "/var/lib/device-inventory.json",
        "/var/lib/inventory/devices.json",
        "/etc/inventory/network-devices.csv",
        "C:\\ProgramData\\IT\\inventory.json",
        "C:\\ProgramData\\Inventory\\devices.xml",
    ]

    # Tool comuni di gestione inventario
    INVENTORY_TOOLS = [
        # Linux
        {"name": "ocs-inventory", "process": "ocs-agent", "service": "ocsinventory-agent"},
        {"name": "glpi-agent", "process": "glpi-agent", "service": "glpi-agent"},
        {"name": "snmpd", "process": "snmpd", "service": "snmpd"},
        # Windows
        {"name": "OCS Inventory Agent", "process": "OCSInventory.exe", "service": "OCS_AGENT_SERVICE"},
        {"name": "GLPI Agent", "process": "GLPI-Agent.exe", "service": "GLPI-AGENT"},
    ]

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Esegue il controllo sull'esistenza dell'inventario.

        Args:
            target: Target su cui eseguire il controllo
            params: Parametri aggiuntivi per il controllo (opzionale)

        Returns:
            Dizionario con i risultati del controllo
        """
        params = params or {}
        start_time = time.time()
        result = self.prepare_result()

        try:
            self.log_check_start(target)

            # 1. Verifica file di inventario comuni
            inventory_files = self._check_common_inventory_files(target)

            # 2. Controlla software di gestione asset
            asset_tools = self._check_asset_management_tools(target)

            # 3. Esegui discovery di rete per confronto
            discovered_devices = self._perform_network_discovery(target, params)

            # 4. Determina se l'inventario è aggiornato automaticamente
            auto_update = self._check_auto_update_mechanisms(target)

            # Compila i risultati
            result['raw_data'] = {
                'inventory_files': inventory_files,
                'asset_tools': asset_tools,
                'discovered_devices': len(discovered_devices),
                'auto_update_mechanism': auto_update
            }

            # Determina lo stato
            if inventory_files or asset_tools:
                if auto_update:
                    result['status'] = "Sì con aggiornamento automatico"
                else:
                    result['status'] = "Sì"
            else:
                result['status'] = "No"

            # Calcola punteggio
            result['score'] = self.calculate_score(result['status'])

            # Aggiungi dettagli
            result['details'] = {
                'found_inventory': bool(inventory_files or asset_tools),
                'auto_updated': auto_update,
                'inventory_files': [f['path'] for f in inventory_files],
                'inventory_tools': [t['name'] for t in asset_tools],
                'coverage': self._calculate_coverage(discovered_devices, inventory_files, asset_tools)
            }

            # Aggiungi note
            if result['status'] == "No":
                result[
                    'notes'] = "Non è stato trovato alcun inventario delle risorse di rete. È necessario implementare un sistema di inventario."
            elif result['status'] == "Sì":
                result[
                    'notes'] = "È presente un inventario, ma manca un meccanismo di aggiornamento automatico. Si consiglia di implementare una soluzione di scoperta automatica."
            else:
                result['notes'] = "Inventario presente con meccanismo di aggiornamento automatico."

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
        Verifica la presenza di file di inventario comuni.

        Args:
            target: Target su cui verificare

        Returns:
            Lista di dizionari con informazioni sui file trovati
        """
        self.logger.debug(f"Checking common inventory files on {target.name}")
        found_files = []

        # Controlla i percorsi comuni
        for path in self.INVENTORY_COMMON_PATHS:
            if self.check_file_exists(target, path):
                self.logger.info(f"Found inventory file on {target.name}: {path}")

                # Leggi la data di modifica del file
                last_modified = self._get_file_last_modified(target, path)

                # Tenta di determinare il formato
                file_format = self._determine_file_format(path)

                # Aggiungi alle informazioni
                found_files.append({
                    'path': path,
                    'last_modified': last_modified,
                    'format': file_format
                })

        # Cerca anche nei percorsi comuni specifici dell'organizzazione
        org_paths = self._get_organization_inventory_paths(target)
        for path in org_paths:
            if self.check_file_exists(target, path):
                self.logger.info(f"Found organization-specific inventory file on {target.name}: {path}")

                # Leggi la data di modifica del file
                last_modified = self._get_file_last_modified(target, path)

                # Tenta di determinare il formato
                file_format = self._determine_file_format(path)

                # Aggiungi alle informazioni
                found_files.append({
                    'path': path,
                    'last_modified': last_modified,
                    'format': file_format
                })

        return found_files

    def _check_asset_management_tools(self, target: Target) -> List[Dict]:
        """
        Verifica la presenza di strumenti di gestione inventario.

        Args:
            target: Target su cui verificare

        Returns:
            Lista di dizionari con informazioni sugli strumenti trovati
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
        Esegue una discovery della rete per trovare dispositivi attivi.

        Args:
            target: Target su cui eseguire la discovery
            params: Parametri aggiuntivi

        Returns:
            Lista di dizionari con informazioni sui dispositivi trovati
        """
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
        Verifica se esistono meccanismi di aggiornamento automatico dell'inventario.

        Args:
            target: Target su cui verificare

        Returns:
            True se esistono meccanismi di aggiornamento automatico
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
        Verifica la presenza di attività pianificate per l'aggiornamento dell'inventario.

        Args:
            target: Target su cui verificare

        Returns:
            True se esistono attività pianificate per l'inventario
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
        Verifica la presenza di servizi di discovery automatica.

        Args:
            target: Target su cui verificare

        Returns:
            True se esistono servizi di discovery automatica
        """
        # Lista di servizi comuni di discovery
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

        # Controlla se uno di questi servizi è in esecuzione
        for service in discovery_services:
            status = self.check_service_status(target, service)
            if status.get('running', False):
                return True

        return False

    def _calculate_coverage(self, discovered_devices: List[Dict], inventory_files: List[Dict],
                            asset_tools: List[Dict]) -> float:
        """
        Calcola la copertura dell'inventario rispetto alla rete.

        Args:
            discovered_devices: Dispositivi scoperti dalla discovery
            inventory_files: File di inventario trovati
            asset_tools: Strumenti di gestione inventario trovati

        Returns:
            Percentuale di copertura (0-100)
        """
        # Questa è una implementazione semplificata
        # In un sistema reale, si leggerebbero i file di inventario e si confronterebbero con i risultati della discovery

        if not discovered_devices:
            return 0

        # Se ci sono strumenti di gestione asset attivi, assumiamo una buona copertura
        if asset_tools:
            return 90.0

        # Se ci sono file di inventario, assumiamo una copertura media
        if inventory_files:
            # Controlla quanto sono recenti i file
            now = time.time()
            max_age_days = 30  # Considera vecchio un file con più di 30 giorni

            for file_info in inventory_files:
                last_modified = file_info.get('last_modified', 0)
                age_days = (now - last_modified) / (60 * 60 * 24)

                if age_days <= max_age_days:
                    return 70.0  # File recente, copertura media

            return 40.0  # File vecchio, copertura bassa

        return 0  # Nessun inventario trovato

    def _get_file_last_modified(self, target: Target, path: str) -> float:
        """
        Ottiene la data di ultima modifica di un file.

        Args:
            target: Target su cui verificare
            path: Percorso del file

        Returns:
            Timestamp dell'ultima modifica o 0 in caso di errore
        """
        # In un'implementazione reale, questa funzione userebbe il connettore
        # appropriato per ottenere l'ultima data di modifica del file

        # Per ora restituiamo un timestamp recente per simulare
        return time.time() - (3 * 24 * 60 * 60)  # 3 giorni fa

    def _determine_file_format(self, path: str) -> str:
        """
        Determina il formato di un file di inventario in base all'estensione.

        Args:
            path: Percorso del file

        Returns:
            Formato del file (json, xml, csv, txt, unknown)
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
        Ottiene i percorsi specifici dell'organizzazione per i file di inventario.

        Args:
            target: Target su cui verificare

        Returns:
            Lista di percorsi potenziali
        """
        # In un'implementazione reale, questa funzione potrebbe
        # consultare una configurazione o interrogare il sistema
        # per trovare i percorsi specifici dell'organizzazione

        # Restituiamo alcuni percorsi comuni aggiuntivi
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


class DeviceDiscoveryCheck(BaseCheck):
    """
    Controllo per verificare l'implementazione di un sistema di rilevamento dispositivi (ABSC 1.1.3-1.1.4).

    Verifica se è implementato un sistema di rilevamento di nuovi dispositivi con generazione di allarmi in caso di anomalie.
    """

    ID = "1.1.3-1.1.4"
    NAME = "Rilevamento dispositivi di rete"
    DESCRIPTION = "Rilevamento dispositivi e analisi del traffico con generazione di allarmi"
    QUESTION = "È implementato un sistema di rilevamento di nuovi dispositivi con generazione di allarmi in caso di anomalie?"
    POSSIBLE_ANSWERS = ["Sì con analisi del traffico", "Sì con discovery", "Sì con allarmi", "Sì completo", "No"]
    CATEGORY = "Inventory"
    PRIORITY = 1  # Alta priorità

    # Tool comuni per il rilevamento dei dispositivi
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
        Esegue il controllo sull'implementazione di un sistema di rilevamento dispositivi.

        Args:
            target: Target su cui eseguire il controllo
            params: Parametri aggiuntivi per il controllo (opzionale)

        Returns:
            Dizionario con i risultati del controllo
        """
        params = params or {}
        start_time = time.time()
        result = self.prepare_result()

        try:
            self.log_check_start(target)

            # 1. Verifica la presenza di tool di discovery
            discovery_tools = self._check_discovery_tools(target)

            # 2. Verifica la capacità di analisi del traffico
            traffic_analysis = self._check_traffic_analysis(target)

            # 3. Verifica la generazione di allarmi
            alarm_capability = self._check_alarm_capability(target)

            # Compila i risultati
            result['raw_data'] = {
                'discovery_tools': discovery_tools,
                'traffic_analysis': traffic_analysis,
                'alarm_capability': alarm_capability
            }

            # Determina lo stato
            if discovery_tools and traffic_analysis and alarm_capability:
                result['status'] = "Sì completo"
            elif discovery_tools and traffic_analysis:
                result['status'] = "Sì con analisi del traffico"
            elif discovery_tools and alarm_capability:
                result['status'] = "Sì con allarmi"
            elif discovery_tools:
                result['status'] = "Sì con discovery"
            else:
                result['status'] = "No"

            # Calcola punteggio
            result['score'] = self._calculate_custom_score(result['status'])

            # Aggiungi dettagli
            result['details'] = {
                'has_discovery_tools': bool(discovery_tools),
                'has_traffic_analysis': traffic_analysis,
                'has_alarm_capability': alarm_capability,
                'discovery_tools': [t['name'] for t in discovery_tools],
            }

            # Aggiungi note
            if result['status'] == "No":
                result[
                    'notes'] = "Non è stato trovato alcun sistema di rilevamento dispositivi. È necessario implementare una soluzione."
            elif result['status'] == "Sì con discovery":
                result[
                    'notes'] = "È presente un sistema di discovery, ma mancano funzionalità di analisi del traffico e generazione allarmi."
            elif result['status'] == "Sì con allarmi":
                result['notes'] = "È presente un sistema di discovery con allarmi, ma manca l'analisi del traffico."
            elif result['status'] == "Sì con analisi del traffico":
                result[
                    'notes'] = "È presente un sistema di discovery con analisi del traffico, ma manca la generazione allarmi."
            else:
                result['notes'] = "Sistema completo di discovery, analisi del traffico e generazione allarmi."

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
        Verifica la presenza di tool per il rilevamento dei dispositivi.

        Args:
            target: Target su cui verificare

        Returns:
            Lista di dizionari con informazioni sui tool trovati
        """
        self.logger.debug(f"Checking discovery tools on {target.name}")
        found_tools = []

        for tool in self.DISCOVERY_TOOLS:
            # Controlla se il processo è in esecuzione
            process_running = self.check_process_running(target, tool['process'])

            # Controlla lo stato del servizio
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
        Verifica se il sistema è in grado di analizzare il traffico di rete.

        Args:
            target: Target su cui verificare

        Returns:
            True se è presente un sistema di analisi del traffico
        """
        self.logger.debug(f"Checking traffic analysis capability on {target.name}")

        # Controlla la presenza di tool specifici per l'analisi del traffico
        traffic_analysis_tools = [
            "snort", "suricata", "wireshark", "ntopng", "zeek", "argus", "tcpdump",
            "netflow", "sflow", "ipfix", "packetbeat", "moloch", "nprobe"
        ]

        for tool in traffic_analysis_tools:
            if self.check_process_running(target, tool):
                self.logger.info(f"Found traffic analysis tool on {target.name}: {tool}")
                return True

        # Controlla anche i file di configurazione dei tool di discovery trovati in precedenza
        for tool in self.DISCOVERY_TOOLS:
            if tool['name'] == "Nagios":
                # Controlla la configurazione di Nagios per il monitoraggio del traffico
                config_path = "/etc/nagios/nrpe.d/traffic.cfg"
                if self.check_file_exists(target, config_path):
                    return True
            elif tool['name'] == "Zabbix":
                # Controlla la configurazione di Zabbix per il monitoraggio del traffico
                config_path = "/etc/zabbix/zabbix_agentd.d/traffic.conf"
                if self.check_file_exists(target, config_path):
                    return True
            elif tool['name'] == "PRTG":
                # PRTG include sensori di traffico per default
                return True

        return False

    def _check_alarm_capability(self, target: Target) -> bool:
        """
        Verifica se il sistema è in grado di generare allarmi per nuovi dispositivi o anomalie.

        Args:
            target: Target su cui verificare

        Returns:
            True se è presente un sistema di generazione allarmi
        """
        self.logger.debug(f"Checking alarm capability on {target.name}")

        # Controlla la presenza di file di log contenenti allarmi
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

        # Controlla anche i servizi di alert
        alert_services = ["nagios-alerter", "zabbix-alerter", "snort-alert", "alertmanager"]
        for service in alert_services:
            status = self.check_service_status(target, service)
            if status.get('running', False):
                self.logger.info(f"Found alert service on {target.name}: {service}")
                return True

        # Controlla i tool di monitoraggio che supportano gli allarmi per default
        for tool in self.DISCOVERY_TOOLS:
            if tool['name'] in ["Nagios", "Zabbix", "PRTG", "Solarwinds"]:
                # Questi tool supportano gli allarmi per default
                if self.check_process_running(target, tool['process']) or self.check_service_status(target, tool[
                    'service']).get('running', False):
                    return True

        return False

    def _calculate_custom_score(self, status: str) -> float:
        """
        Calcola un punteggio personalizzato in base allo stato.

        Args:
            status: Stato del controllo

        Returns:
            Punteggio da 0 a 100
        """
        if status == "Sì completo":
            return 100
        elif status == "Sì con analisi del traffico":
            return 80
        elif status == "Sì con allarmi":
            return 70
        elif status == "Sì con discovery":
            return 50
        elif status == "No":
            return 0
        else:
            return 0


class DHCPMonitoringCheck(BaseCheck):
    """
    Controllo per verificare il monitoraggio dei log DHCP (ABSC 1.2.1-1.2.2).

    Verifica se i log del server DHCP vengono monitorati e utilizzati per migliorare l'inventario.
    """

    ID = "1.2.1-1.2.2"
    NAME = "Monitoraggio dei log DHCP"
    DESCRIPTION = "Monitoraggio e analisi dei log DHCP per migliorare l'inventario"
    QUESTION = "I log del server DHCP vengono monitorati e utilizzati per migliorare l'inventario?"
    POSSIBLE_ANSWERS = ["Sì", "No"]
    CATEGORY = "Inventory"
    PRIORITY = 2  # Media priorità

    # Percorsi comuni per i log DHCP
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
        Esegue il controllo sul monitoraggio dei log DHCP.

        Args:
            target: Target su cui eseguire il controllo
            params: Parametri aggiuntivi per il controllo (opzionale)

        Returns:
            Dizionario con i risultati del controllo
        """
        params = params or {}
        start_time = time.time()
        result = self.prepare_result()

        try:
            self.log_check_start(target)

            # 1. Verifica la presenza di log DHCP
            dhcp_logs = self._check_dhcp_logs(target)

            # 2. Verifica la presenza di script o procedure per l'analisi dei log
            analysis_scripts = self._check_analysis_scripts(target)

            # 3. Verifica l'integrazione con l'inventario
            inventory_integration = self._check_inventory_integration(target)

            # Compila i risultati
            result['raw_data'] = {
                'dhcp_logs': dhcp_logs,
                'analysis_scripts': analysis_scripts,
                'inventory_integration': inventory_integration
            }

            # Determina lo stato
            if dhcp_logs and (analysis_scripts or inventory_integration):
                result['status'] = "Sì"
            else:
                result['status'] = "No"

            # Calcola punteggio
            result['score'] = self.calculate_score(result['status'])

            # Aggiungi dettagli
            result['details'] = {
                'has_dhcp_logs': bool(dhcp_logs),
                'has_analysis_scripts': bool(analysis_scripts),
                'has_inventory_integration': inventory_integration,
                'dhcp_log_paths': [log['path'] for log in dhcp_logs],
                'analysis_script_paths': [script['path'] for script in analysis_scripts]
            }

            # Aggiungi note
            if result['status'] == "No":
                if dhcp_logs:
                    result[
                        'notes'] = "I log DHCP sono presenti ma non vengono analizzati o utilizzati per aggiornare l'inventario."
                else:
                    result[
                        'notes'] = "Non sono stati trovati log DHCP sul sistema. Verificare che il server DHCP sia configurato per il logging."
            else:
                result['notes'] = "I log DHCP vengono monitorati e utilizzati per migliorare l'inventario."

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
        Verifica la presenza di log DHCP sul target.

        Args:
            target: Target su cui verificare

        Returns:
            Lista di dizionari con informazioni sui log trovati
        """
        self.logger.debug(f"Checking DHCP logs on {target.name}")
        found_logs = []

        # Controlla i percorsi comuni
        for path in self.DHCP_LOG_PATHS:
            if self.check_file_exists(target, path):
                self.logger.info(f"Found DHCP log on {target.name}: {path}")

                # Leggi la data di modifica del file
                last_modified = self._get_file_last_modified(target, path)

                # Controlla se il file è stato modificato di recente (ultime 24 ore)
                is_active = (time.time() - last_modified) < (24 * 60 * 60)

                # Aggiungi alle informazioni
                found_logs.append({
                    'path': path,
                    'last_modified': last_modified,
                    'is_active': is_active
                })

        # Controlla anche la configurazione del server DHCP per verificare il logging
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
        Verifica la presenza di script o procedure per l'analisi dei log DHCP.

        Args:
            target: Target su cui verificare

        Returns:
            Lista di dizionari con informazioni sugli script trovati
        """
        self.logger.debug(f"Checking DHCP log analysis scripts on {target.name}")
        found_scripts = []

        # Controlla la presenza di script comuni per l'analisi dei log DHCP
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

                # Leggi la data di modifica del file
                last_executed = self._get_file_last_modified(target, path)

                # Determina se è stato eseguito di recente (ultimi 7 giorni)
                recently_executed = (time.time() - last_executed) < (7 * 24 * 60 * 60)

                # Aggiungi alle informazioni
                found_scripts.append({
                    'path': path,
                    'last_executed': last_executed,
                    'recently_executed': recently_executed
                })

        # Controlla anche i job cron/scheduled tasks
        if target.os_type.lower() in ['linux', 'unix']:
            # Cerca nei file crontab
            cron_paths = ['/etc/crontab', '/var/spool/cron/crontabs/root']
            for path in cron_paths:
                content = self.read_file_content(target, path)
                if content and re.search(r'dhcp.*log|dhcp.*inventory', content, re.IGNORECASE):
                    self.logger.info(f"Found DHCP analysis cron job on {target.name}: {path}")
                    found_scripts.append({
                        'path': path,
                        'type': 'cron',
                        'recently_executed': True  # Assumiamo che venga eseguito regolarmente
                    })

        elif target.os_type.lower() == 'windows':
            # Esegui il comando schtasks
            result = self.execute_command(target, 'schtasks /query /fo LIST /v | findstr /i "dhcp"')
            if result['exit_code'] == 0 and result['stdout']:
                self.logger.info(f"Found DHCP analysis scheduled task on {target.name}")
                found_scripts.append({
                    'path': 'Windows Scheduled Task',
                    'type': 'scheduled_task',
                    'recently_executed': True  # Assumiamo che venga eseguito regolarmente
                })

        return found_scripts

    def _check_inventory_integration(self, target: Target) -> bool:
        """
        Verifica se i log DHCP sono integrati con l'inventario.

        Args:
            target: Target su cui verificare

        Returns:
            True se c'è integrazione tra DHCP e inventario
        """
        self.logger.debug(f"Checking DHCP integration with inventory on {target.name}")

        # Controlla la presenza di file di configurazione che legano DHCP e inventario
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

        # Controlla anche la presenza di script specifici per l'integrazione
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
        Ottiene la data di ultima modifica di un file.

        Args:
            target: Target su cui verificare
            path: Percorso del file

        Returns:
            Timestamp dell'ultima modifica o 0 in caso di errore
        """
        # In un'implementazione reale, questa funzione userebbe il connettore
        # appropriato per ottenere l'ultima data di modifica del file

        # Per ora restituiamo un timestamp recente per simulare
        return time.time() - (2 * 24 * 60 * 60)  # 2 giorni fa