# absc_audit/utils/network.py

import ipaddress
import socket
import subprocess
from typing import List, Dict, Optional

from absc_audit.storage.models import Target
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


def ping(host: str, count: int = 1, timeout: int = 2) -> bool:
    """
    Esegue un ping su un host.

    Args:
        host: Hostname o indirizzo IP
        count: Numero di pacchetti da inviare
        timeout: Timeout in secondi

    Returns:
        True se il ping ha successo, False altrimenti
    """
    try:
        # Comando di ping diverso in base al sistema operativo
        import platform
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'

        command = ['ping', param, str(count), timeout_param, str(timeout), host]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception as e:
        logger.error(f"Error during ping to {host}: {str(e)}")
        return False


def scan_network(target: Target, network_range: str) -> List[Dict]:
    """
    Esegue una scansione di rete per trovare dispositivi attivi.

    Args:
        target: Target da cui eseguire la scansione
        network_range: Range di rete da scansionare (CIDR notation)

    Returns:
        Lista di dizionari con informazioni sui dispositivi trovati
    """
    # Questa è una versione semplificata che utilizza solo ping
    # In un'implementazione reale, si potrebbe utilizzare nmap o altre utility

    devices = []

    try:
        # Converti il range CIDR in una lista di indirizzi IP
        network = ipaddress.ip_network(network_range)

        for ip in network.hosts():
            ip_str = str(ip)
            if ping(ip_str):
                # Tenta di risolvere il nome host
                try:
                    hostname = socket.gethostbyaddr(ip_str)[0]
                except socket.herror:
                    hostname = ""

                devices.append({
                    'ip': ip_str,
                    'hostname': hostname,
                    'mac': get_mac_address(ip_str),
                    'type': 'unknown'
                })

        return devices

    except Exception as e:
        logger.error(f"Error scanning network {network_range}: {str(e)}")
        return []


def get_mac_address(ip: str) -> Optional[str]:
    """
    Ottiene l'indirizzo MAC di un dispositivo.

    Args:
        ip: Indirizzo IP del dispositivo

    Returns:
        Indirizzo MAC o None se non trovato
    """
    try:
        # Questa è una versione semplificata
        # In un'implementazione reale, si potrebbe utilizzare ARP

        import platform
        if platform.system().lower() == 'windows':
            # Windows
            output = subprocess.check_output(['arp', '-a', ip]).decode('utf-8')
            for line in output.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1].replace('-', ':')
        else:
            # Linux/Unix
            output = subprocess.check_output(['arp', '-n', ip]).decode('utf-8')
            for line in output.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]

        return None

    except Exception as e:
        logger.error(f"Error getting MAC address for {ip}: {str(e)}")
        return None


def parse_network_discovery(output: str) -> List[Dict]:
    """
    Analizza l'output di una scansione di rete.

    Args:
        output: Output della scansione

    Returns:
        Lista di dizionari con informazioni sui dispositivi trovati
    """
    # Questa è una versione semplificata per parsare l'output di nmap
    # In un'implementazione reale, si potrebbe utilizzare python-nmap

    devices = []

    try:
        # Analisi molto semplificata dell'output di nmap
        current_ip = None
        current_host = {}

        for line in output.splitlines():
            line = line.strip()

            # Indirizzo IP
            if line.startswith('Nmap scan report for'):
                # Salva l'host precedente se presente
                if current_ip and current_host:
                    devices.append(current_host)

                # Estrai IP e hostname
                parts = line.split(' ', 5)
                if len(parts) >= 5:
                    current_ip = parts[-1].strip('()')
                    hostname = parts[-2] if '(' in line else ""
                    current_host = {
                        'ip': current_ip,
                        'hostname': hostname,
                        'mac': None,
                        'type': 'unknown'
                    }

            # Indirizzo MAC
            elif 'MAC Address:' in line:
                parts = line.split(':', 1)
                if len(parts) >= 2:
                    mac_parts = parts[1].split('(')
                    current_host['mac'] = mac_parts[0].strip()
                    if len(mac_parts) >= 2:
                        current_host['type'] = mac_parts[1].strip('()')

        # Aggiungi l'ultimo host
        if current_ip and current_host:
            devices.append(current_host)

        return devices

    except Exception as e:
        logger.error(f"Error parsing network discovery output: {str(e)}")
        return []