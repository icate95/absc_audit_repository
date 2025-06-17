"""
SSH Connector - Implementazione del connettore SSH.

Questo modulo implementa il connettore SSH per l'interazione
con sistemi Linux/Unix tramite il protocollo SSH.
"""

import os
import socket
import time
from typing import Dict, List, Optional, Any, Union, Tuple

# Importazioni condizionali per gestire le dipendenze
try:
    import paramiko

    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

from absc_audit.connectors.base import BaseConnector
from absc_audit.storage.models import Target
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class SSHConnector(BaseConnector):
    """
    Connettore SSH per l'interazione con sistemi Linux/Unix.

    Questa classe implementa il connettore per interagire con sistemi
    Linux/Unix tramite il protocollo SSH.
    """

    def __init__(self, target: Target = None, **kwargs):
        """
        Inizializza il connettore SSH.

        Args:
            target: Target su cui operare (opzionale)
            **kwargs: Parametri aggiuntivi specifici del connettore SSH
        """
        super().__init__(target, **kwargs)

        if not HAS_PARAMIKO:
            self.log_error("Paramiko module not installed. SSH connector will not function.")
            raise ImportError("Paramiko module not installed. Install with 'pip install paramiko'")

        # Parametri SSH
        self.hostname = kwargs.get('hostname', target.hostname if target else None)
        self.port = kwargs.get('port', 22)
        self.username = kwargs.get('username', 'root')
        self.password = kwargs.get('password', None)
        self.key_filename = kwargs.get('key_filename', None)
        self.timeout = kwargs.get('timeout', 30)
        self.allow_agent = kwargs.get('allow_agent', True)
        self.look_for_keys = kwargs.get('look_for_keys', True)

        # Inizializza gli attributi di connessione
        self.client = None
        self.sftp = None

    def connect(self) -> bool:
        """
        Stabilisce una connessione SSH con il target.

        Returns:
            True se la connessione ha successo, False altrimenti
        """
        if self.is_connected():
            return True

        if not self.hostname:
            self.log_error("No hostname specified for SSH connection")
            return False

        try:
            self.log_debug(f"Connecting to {self.hostname}:{self.port} as {self.username}")

            # Crea il client SSH
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Tenta la connessione
            self.client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                key_filename=self.key_filename,
                timeout=self.timeout,
                allow_agent=self.allow_agent,
                look_for_keys=self.look_for_keys
            )

            # Ottieni una sessione SFTP
            self.sftp = self.client.open_sftp()

            self.connected = True
            self.log_info(f"Successfully connected to {self.hostname}")
            return True

        except (paramiko.AuthenticationException, paramiko.SSHException, socket.error) as e:
            self.log_error(f"Failed to connect to {self.hostname}: {str(e)}", e)
            self.connected = False
            return False

    def disconnect(self) -> bool:
        """
        Chiude la connessione SSH con il target.

        Returns:
            True se la disconnessione ha successo, False altrimenti
        """
        try:
            if self.sftp:
                self.sftp.close()
                self.sftp = None

            if self.client:
                self.client.close()
                self.client = None

            self.connected = False
            self.log_debug(f"Disconnected from {self.hostname}")
            return True

        except Exception as e:
            self.log_error(f"Error disconnecting from {self.hostname}: {str(e)}", e)
            return False

    def is_connected(self) -> bool:
        """
        Verifica se la connessione SSH è attiva.

        Returns:
            True se la connessione è attiva, False altrimenti
        """
        if not self.client or not self.connected:
            return False

        try:
            # Esegui un comando semplice per verificare la connessione
            transport = self.client.get_transport()
            if transport and transport.is_active():
                transport.send_ignore()
                return True
            return False

        except (EOFError, paramiko.SSHException):
            self.connected = False
            return False

    def execute_command(self, command: str, timeout: int = 30, use_sudo: bool = False) -> Dict:
        """
        Esegue un comando sul target tramite SSH.

        Args:
            command: Comando da eseguire
            timeout: Timeout in secondi
            use_sudo: Se utilizzare sudo per l'esecuzione

        Returns:
            Dizionario con stdout, stderr e codice di uscita
        """
        if not self.is_connected() and not self.connect():
            return {
                'stdout': '',
                'stderr': 'Not connected to target',
                'exit_code': -1
            }

        try:
            # Aggiungi sudo se richiesto
            if use_sudo and not command.startswith('sudo '):
                command = f'sudo {command}'

            self.log_debug(f"Executing command: {command}")

            # Esegui il comando
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)

            # Leggi l'output
            stdout_data = stdout.read().decode('utf-8', errors='replace')
            stderr_data = stderr.read().decode('utf-8', errors='replace')
            exit_code = stdout.channel.recv_exit_status()

            if exit_code != 0:
                self.log_debug(f"Command exited with code {exit_code}: {stderr_data}")

            return {
                'stdout': stdout_data,
                'stderr': stderr_data,
                'exit_code': exit_code
            }

        except (paramiko.SSHException, socket.error, socket.timeout) as e:
            self.log_error(f"Error executing command: {str(e)}", e)
            self.connected = False
            return {
                'stdout': '',
                'stderr': str(e),
                'exit_code': -1
            }

    def check_file_exists(self, path: str) -> bool:
        """
        Verifica se un file esiste sul target tramite SFTP.

        Args:
            path: Percorso del file da verificare

        Returns:
            True se il file esiste, False altrimenti
        """
        if not self.is_connected() and not self.connect():
            return False

        try:
            self.log_debug(f"Checking if file exists: {path}")

            # Tenta di ottenere le informazioni sul file
            self.sftp.stat(path)
            return True

        except FileNotFoundError:
            return False

        except (paramiko.SSHException, IOError) as e:
            self.log_error(f"Error checking if file exists: {str(e)}", e)
            return False

    def read_file_content(self, path: str) -> Optional[str]:
        """
        Legge il contenuto di un file sul target tramite SFTP.

        Args:
            path: Percorso del file da leggere

        Returns:
            Contenuto del file o None in caso di errore
        """
        if not self.is_connected() and not self.connect():
            return None

        try:
            self.log_debug(f"Reading file content: {path}")

            # Usa SFTP per leggere il file
            with self.sftp.open(path, 'r') as f:
                content = f.read().decode('utf-8', errors='replace')
                return content

        except FileNotFoundError:
            self.log_debug(f"File not found: {path}")
            return None

        except (paramiko.SSHException, IOError, UnicodeDecodeError) as e:
            self.log_error(f"Error reading file content: {str(e)}", e)
            return None

    def check_process_running(self, process_name: str) -> bool:
        """
        Verifica se un processo è in esecuzione sul target tramite SSH.

        Args:
            process_name: Nome del processo da verificare

        Returns:
            True se il processo è in esecuzione, False altrimenti
        """
        # Esegui il comando 'pgrep' per cercare il processo
        result = self.execute_command(f"pgrep -f {process_name}")

        # Verifica il codice di uscita (0 significa che il processo è stato trovato)
        return result['exit_code'] == 0

    def check_service_status(self, service_name: str) -> Dict:
        """
        Verifica lo stato di un servizio sul target tramite SSH.

        Args:
            service_name: Nome del servizio da verificare

        Returns:
            Dizionario con informazioni sullo stato del servizio
        """
        # Prepara il risultato di default
        result = {
            'running': False,
            'enabled': False,
            'error': None
        }

        # Verifica se il servizio è in esecuzione (systemctl)
        systemctl_result = self.execute_command(f"systemctl is-active {service_name}")
        if systemctl_result['exit_code'] == 0:
            result['running'] = systemctl_result['stdout'].strip() == 'active'

            # Verifica se il servizio è abilitato all'avvio
            enabled_result = self.execute_command(f"systemctl is-enabled {service_name}")
            result['enabled'] = enabled_result['exit_code'] == 0 and enabled_result['stdout'].strip() == 'enabled'

            return result

        # Fallback su service (per sistemi più vecchi)
        service_result = self.execute_command(f"service {service_name} status")
        if service_result['exit_code'] == 0:
            output = service_result['stdout'].lower()
            result['running'] = 'running' in output or 'active' in output

            # Non sempre possiamo determinare se è abilitato all'avvio con 'service'
            # Tentiamo con chkconfig se disponibile
            chkconfig_result = self.execute_command(f"chkconfig --list {service_name}")
            if chkconfig_result['exit_code'] == 0:
                result['enabled'] = ':on' in chkconfig_result['stdout'].lower()

            return result

        # Prova anche con "/etc/init.d"
        init_result = self.execute_command(f"/etc/init.d/{service_name} status")
        if init_result['exit_code'] == 0:
            output = init_result['stdout'].lower()
            result['running'] = 'running' in output or 'active' in output

            return result

        # Servizio non trovato o errore
        result['error'] = "Service not found or status check failed"
        return result

    def get_os_info(self) -> Dict:
        """
        Ottiene informazioni sul sistema operativo del target.

        Returns:
            Dizionario con informazioni sul sistema operativo
        """
        os_info = {
            'os_name': None,
            'os_version': None,
            'os_release': None,
            'kernel': None
        }

        # Prova a leggere /etc/os-release
        if self.check_file_exists('/etc/os-release'):
            os_release = self.read_file_content('/etc/os-release')
            if os_release:
                lines = os_release.splitlines()
                for line in lines:
                    if '=' in line:
                        key, value = line.split('=', 1)
                        value = value.strip('"\'')
                        if key == 'NAME':
                            os_info['os_name'] = value
                        elif key == 'VERSION_ID':
                            os_info['os_version'] = value
                        elif key == 'PRETTY_NAME':
                            os_info['os_release'] = value

        # Ottieni la versione del kernel
        kernel_result = self.execute_command('uname -r')
        if kernel_result['exit_code'] == 0:
            os_info['kernel'] = kernel_result['stdout'].strip()

        return os_info

    def get_hardware_info(self) -> Dict:
        """
        Ottiene informazioni sull'hardware del target.

        Returns:
            Dizionario con informazioni sull'hardware
        """
        hw_info = {
            'cpu_model': None,
            'cpu_count': None,
            'memory_total': None,
            'disk_total': None
        }

        # CPU Model
        cpu_result = self.execute_command("cat /proc/cpuinfo | grep 'model name' | head -n1")
        if cpu_result['exit_code'] == 0 and cpu_result['stdout']:
            parts = cpu_result['stdout'].split(':', 1)
            if len(parts) > 1:
                hw_info['cpu_model'] = parts[1].strip()

        # CPU Count
        count_result = self.execute_command("grep -c ^processor /proc/cpuinfo")
        if count_result['exit_code'] == 0 and count_result['stdout']:
            try:
                hw_info['cpu_count'] = int(count_result['stdout'].strip())
            except ValueError:
                pass

        # Memory Total
        mem_result = self.execute_command("grep MemTotal /proc/meminfo")
        if mem_result['exit_code'] == 0 and mem_result['stdout']:
            parts = mem_result['stdout'].split(':', 1)
            if len(parts) > 1:
                try:
                    mem_kb = int(parts[1].strip().split()[0])
                    hw_info['memory_total'] = f"{mem_kb // 1024} MB"
                except (ValueError, IndexError):
                    pass

        # Disk Total
        disk_result = self.execute_command("df -h / | tail -n1")
        if disk_result['exit_code'] == 0 and disk_result['stdout']:
            parts = disk_result['stdout'].split()
            if len(parts) >= 2:
                hw_info['disk_total'] = parts[1]

        return hw_info

    def get_installed_packages(self) -> List[Dict]:
        """
        Ottiene la lista dei pacchetti installati sul target.

        Returns:
            Lista di dizionari con informazioni sui pacchetti
        """
        packages = []

        # Tenta con dpkg (Debian/Ubuntu)
        dpkg_result = self.execute_command("dpkg-query -W -f='${Package} ${Version}\n'")
        if dpkg_result['exit_code'] == 0 and dpkg_result['stdout']:
            for line in dpkg_result['stdout'].splitlines():
                parts = line.split(' ', 1)
                if len(parts) >= 2:
                    packages.append({
                        'name': parts[0],
                        'version': parts[1],
                        'source': 'dpkg'
                    })
            return packages

        # Tenta con rpm (RHEL/CentOS/Fedora)
        rpm_result = self.execute_command("rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n'")
        if rpm_result['exit_code'] == 0 and rpm_result['stdout']:
            for line in rpm_result['stdout'].splitlines():
                parts = line.split(' ', 1)
                if len(parts) >= 2:
                    packages.append({
                        'name': parts[0],
                        'version': parts[1],
                        'source': 'rpm'
                    })
            return packages

        # Fallback generico
        self.log_debug("Could not determine package manager, using simplified approach")
        return packages