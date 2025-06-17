"""
WMI Connector - Implementazione del connettore WMI per Windows.

Questo modulo implementa il connettore WMI per l'interazione
con sistemi Windows tramite il protocollo WMI/DCOM.
"""

import os
import socket
import time
import re
from typing import Dict, List, Optional, Any, Union, Tuple

# Importazioni condizionali per gestire le dipendenze
try:
    import wmi
    import pythoncom

    HAS_WMI = True
except ImportError:
    HAS_WMI = False

from absc_audit.connectors.base import BaseConnector
from absc_audit.storage.models import Target
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class WMIConnector(BaseConnector):
    """
    Connettore WMI per l'interazione con sistemi Windows.

    Questa classe implementa il connettore per interagire con sistemi
    Windows tramite il protocollo WMI (Windows Management Instrumentation).
    """

    def __init__(self, target: Target = None, **kwargs):
        """
        Inizializza il connettore WMI.

        Args:
            target: Target su cui operare (opzionale)
            **kwargs: Parametri aggiuntivi specifici del connettore WMI
        """
        super().__init__(target, **kwargs)

        if not HAS_WMI:
            self.log_error("WMI module not installed. WMI connector will not function.")
            raise ImportError("WMI module not installed. Install with 'pip install wmi pywin32'")

        # Parametri WMI
        self.hostname = kwargs.get('hostname', target.hostname if target else None)
        self.username = kwargs.get('username', None)
        self.password = kwargs.get('password', None)
        self.domain = kwargs.get('domain', '')
        self.namespace = kwargs.get('namespace', 'root\\cimv2')
        self.timeout = kwargs.get('timeout', 30)

        # Inizializza gli attributi di connessione
        self.conn = None

    def connect(self) -> bool:
        """
        Stabilisce una connessione WMI con il target.

        Returns:
            True se la connessione ha successo, False altrimenti
        """
        if self.is_connected():
            return True

        if not self.hostname:
            self.log_error("No hostname specified for WMI connection")
            return False

        try:
            self.log_debug(f"Connecting to {self.hostname} via WMI as {self.username}")

            # Inizializza COM per il thread corrente
            pythoncom.CoInitialize()

            # Crea la connessione WMI
            if self.username and self.password:
                self.conn = wmi.WMI(
                    computer=self.hostname,
                    user=f"{self.domain}\\{self.username}" if self.domain else self.username,
                    password=self.password,
                    namespace=self.namespace
                )
            else:
                # Connessione con le credenziali correnti
                self.conn = wmi.WMI(computer=self.hostname, namespace=self.namespace)

            # Verifica che la connessione sia stabilita facendo una query semplice
            _ = self.conn.Win32_OperatingSystem()

            self.connected = True
            self.log_info(f"Successfully connected to {self.hostname}")
            return True

        except (wmi.x_wmi, pythoncom.com_error) as e:
            self.log_error(f"Failed to connect to {self.hostname}: {str(e)}", e)
            self.connected = False
            return False

    def disconnect(self) -> bool:
        """
        Chiude la connessione WMI con il target.

        Returns:
            True se la disconnessione ha successo, False altrimenti
        """
        try:
            # Riferimento alla connessione
            self.conn = None

            # Deinitializza COM
            pythoncom.CoUninitialize()

            self.connected = False
            self.log_debug(f"Disconnected from {self.hostname}")
            return True

        except (wmi.x_wmi, pythoncom.com_error) as e:
            self.log_error(f"Error disconnecting from {self.hostname}: {str(e)}", e)
            return False

    def is_connected(self) -> bool:
        """
        Verifica se la connessione WMI è attiva.

        Returns:
            True se la connessione è attiva, False altrimenti
        """
        if not self.conn or not self.connected:
            return False

        try:
            # Verifica che la connessione sia ancora valida facendo una query semplice
            _ = self.conn.Win32_OperatingSystem()
            return True

        except (wmi.x_wmi, pythoncom.com_error):
            self.connected = False
            return False

    def execute_command(self, command: str, timeout: int = 30, use_sudo: bool = False) -> Dict:
        """
        Esegue un comando sul target tramite WMI (Win32_Process).

        Args:
            command: Comando da eseguire
            timeout: Timeout in secondi
            use_sudo: Se utilizzare privilegi amministrativi (ignorato su Windows)

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
            self.log_debug(f"Executing command: {command}")

            # Per eseguire un comando e ottenere l'output, usiamo un file temporaneo
            # Crea dei nomi di file temporanei univoci
            timestamp = int(time.time())
            stdout_file = f"C:\\Windows\\Temp\\wmi_stdout_{timestamp}.txt"
            stderr_file = f"C:\\Windows\\Temp\\wmi_stderr_{timestamp}.txt"
            exit_code_file = f"C:\\Windows\\Temp\\wmi_exit_{timestamp}.txt"

            # Modifica il comando per reindirizzare l'output e scrivere il codice di uscita
            wrapped_command = f'cmd.exe /c "{command} > {stdout_file} 2> {stderr_file} & echo %ERRORLEVEL% > {exit_code_file}"'

            # Esegui il comando
            process_id, return_value = self.conn.Win32_Process.Create(CommandLine=wrapped_command)

            if return_value != 0:
                self.log_error(f"Failed to create process: {return_value}")
                return {
                    'stdout': '',
                    'stderr': f'Failed to create process: {return_value}',
                    'exit_code': -1
                }

            # Attendi il completamento del processo
            start_time = time.time()
            process_completed = False

            while not process_completed and (time.time() - start_time) < timeout:
                # Cerca il processo per ID
                processes = self.conn.Win32_Process(ProcessId=process_id)

                # Se il processo non esiste più, è completato
                if len(processes) == 0:
                    process_completed = True
                    break

                time.sleep(0.5)

            # Se siamo usciti per timeout, tenta di terminare il processo
            if not process_completed:
                self.log_error(f"Command execution timed out after {timeout} seconds")
                for process in self.conn.Win32_Process(ProcessId=process_id):
                    process.Terminate()
                return {
                    'stdout': '',
                    'stderr': f'Command execution timed out after {timeout} seconds',
                    'exit_code': -1
                }

            # Leggi i file di output
            stdout_data = ''
            stderr_data = ''
            exit_code = -1

            # Aspetta un momento per essere sicuri che i file siano stati scritti
            time.sleep(0.5)

            try:
                # Leggi lo stdout
                stdout_content = self._read_file_via_wmi(stdout_file)
                if stdout_content is not None:
                    stdout_data = stdout_content

                # Leggi lo stderr
                stderr_content = self._read_file_via_wmi(stderr_file)
                if stderr_content is not None:
                    stderr_data = stderr_content

                # Leggi il codice di uscita
                exit_code_content = self._read_file_via_wmi(exit_code_file)
                if exit_code_content is not None:
                    try:
                        exit_code = int(exit_code_content.strip())
                    except ValueError:
                        exit_code = -1
            finally:
                # Pulisci i file temporanei
                self._delete_file_via_wmi(stdout_file)
                self._delete_file_via_wmi(stderr_file)
                self._delete_file_via_wmi(exit_code_file)

            if exit_code != 0:
                self.log_debug(f"Command exited with code {exit_code}: {stderr_data}")

            return {
                'stdout': stdout_data,
                'stderr': stderr_data,
                'exit_code': exit_code
            }

        except (wmi.x_wmi, pythoncom.com_error) as e:
            self.log_error(f"Error executing command: {str(e)}", e)
            self.connected = False
            return {
                'stdout': '',
                'stderr': str(e),
                'exit_code': -1
            }

    def check_file_exists(self, path: str) -> bool:
        """
        Verifica se un file esiste sul target tramite WMI.

        Args:
            path: Percorso del file da verificare

        Returns:
            True se il file esiste, False altrimenti
        """
        if not self.is_connected() and not self.connect():
            return False

        try:
            self.log_debug(f"Checking if file exists: {path}")

            # Normalizza il percorso per WMI (usa \\ invece di \)
            path = path.replace('\\', '\\\\')

            # Usa CIM_DataFile per verificare l'esistenza del file
            files = self.conn.query(f"SELECT * FROM CIM_DataFile WHERE Name = '{path}'")

            return len(files) > 0

        except (wmi.x_wmi, pythoncom.com_error) as e:
            self.log_error(f"Error checking if file exists: {str(e)}", e)
            return False

    def read_file_content(self, path: str) -> Optional[str]:
        """
        Legge il contenuto di un file sul target tramite WMI.

        Args:
            path: Percorso del file da leggere

        Returns:
            Contenuto del file o None in caso di errore
        """
        return self._read_file_via_wmi(path)

    def check_process_running(self, process_name: str) -> bool:
        """
        Verifica se un processo è in esecuzione sul target tramite WMI.

        Args:
            process_name: Nome del processo da verificare

        Returns:
            True se il processo è in esecuzione, False altrimenti
        """
        if not self.is_connected() and not self.connect():
            return False

        try:
            self.log_debug(f"Checking if process is running: {process_name}")

            # Cerca il processo per nome
            if '.' in process_name:
                # Se contiene un'estensione, cerca il nome esatto
                processes = self.conn.Win32_Process(Name=process_name)
            else:
                # Altrimenti cerca processi che iniziano con quel nome
                processes = self.conn.query(f"SELECT * FROM Win32_Process WHERE Name LIKE '{process_name}%'")

            return len(processes) > 0

        except (wmi.x_wmi, pythoncom.com_error) as e:
            self.log_error(f"Error checking if process is running: {str(e)}", e)
            return False

    def check_service_status(self, service_name: str) -> Dict:
        """
        Verifica lo stato di un servizio sul target tramite WMI.

        Args:
            service_name: Nome del servizio da verificare

        Returns:
            Dizionario con informazioni sullo stato del servizio
        """
        if not self.is_connected() and not self.connect():
            return {
                'running': False,
                'enabled': False,
                'error': "Not connected to target"
            }

        try:
            self.log_debug(f"Checking service status: {service_name}")

            # Cerca il servizio per nome
            services = self.conn.Win32_Service(Name=service_name)

            if len(services) == 0:
                return {
                    'running': False,
                    'enabled': False,
                    'error': "Service not found"
                }

            # Get the first matching service
            service = services[0]

            # Determine if service is running
            running = service.State == 'Running'

            # Determine if service is enabled (starts automatically)
            enabled = service.StartMode in ['Auto', 'Automatic']

            return {
                'running': running,
                'enabled': enabled,
                'error': None,
                'state': service.State,
                'start_mode': service.StartMode,
                'description': service.Description
            }

        except (wmi.x_wmi, pythoncom.com_error) as e:
            self.log_error(f"Error checking service status: {str(e)}", e)
            return {
                'running': False,
                'enabled': False,
                'error': str(e)
            }

    def get_os_info(self) -> Dict:
        """
        Ottiene informazioni sul sistema operativo del target.

        Returns:
            Dizionario con informazioni sul sistema operativo
        """
        if not self.is_connected() and not self.connect():
            return {
                'os_name': None,
                'os_version': None,
                'os_release': None,
                'os_build': None,
                'os_arch': None
            }

        try:
            self.log_debug("Getting OS information")

            # Ottieni informazioni dal OS
            os_info = self.conn.Win32_OperatingSystem()[0]

            return {
                'os_name': os_info.Caption,
                'os_version': os_info.Version,
                'os_release': os_info.CSDVersion,
                'os_build': os_info.BuildNumber,
                'os_arch': os_info.OSArchitecture
            }

        except (wmi.x_wmi, pythoncom.com_error, IndexError) as e:
            self.log_error(f"Error getting OS information: {str(e)}", e)
            return {
                'os_name': None,
                'os_version': None,
                'os_release': None,
                'os_build': None,
                'os_arch': None
            }

    def get_hardware_info(self) -> Dict:
        """
        Ottiene informazioni sull'hardware del target.

        Returns:
            Dizionario con informazioni sull'hardware
        """
        if not self.is_connected() and not self.connect():
            return {
                'cpu_model': None,
                'cpu_count': None,
                'memory_total': None,
                'disk_total': None
            }

        try:
            self.log_debug("Getting hardware information")

            hw_info = {
                'cpu_model': None,
                'cpu_count': 0,
                'memory_total': None,
                'disk_total': None
            }

            # CPU Model e Count
            processors = self.conn.Win32_Processor()
            if processors:
                hw_info['cpu_model'] = processors[0].Name
                hw_info['cpu_count'] = len(processors)

            # Memory Total
            computer_system = self.conn.Win32_ComputerSystem()[0]
            if hasattr(computer_system, 'TotalPhysicalMemory'):
                total_memory_bytes = int(computer_system.TotalPhysicalMemory)
                hw_info['memory_total'] = f"{total_memory_bytes // (1024 * 1024)} MB"

            # Disk Total
            logical_disks = self.conn.Win32_LogicalDisk(DriveType=3)  # Fixed disks only
            total_disk_bytes = 0
            for disk in logical_disks:
                if hasattr(disk, 'Size'):
                    total_disk_bytes += int(disk.Size)

            if total_disk_bytes > 0:
                hw_info['disk_total'] = f"{total_disk_bytes // (1024 * 1024 * 1024)} GB"

            return hw_info

        except (wmi.x_wmi, pythoncom.com_error, IndexError) as e:
            self.log_error(f"Error getting hardware information: {str(e)}", e)
            return {
                'cpu_model': None,
                'cpu_count': None,
                'memory_total': None,
                'disk_total': None
            }

    def get_installed_software(self) -> List[Dict]:
        """
        Ottiene la lista del software installato sul target.

        Returns:
            Lista di dizionari con informazioni sul software installato
        """
        if not self.is_connected() and not self.connect():
            return []

        try:
            self.log_debug("Getting installed software")

            software_list = []

            # Interroga Win32_Product per il software installato tramite MSI
            products = self.conn.Win32_Product()

            for product in products:
                software_list.append({
                    'name': product.Name,
                    'version': product.Version,
                    'vendor': product.Vendor,
                    'install_date': product.InstallDate,
                    'install_source': 'MSI'
                })

            return software_list

        except (wmi.x_wmi, pythoncom.com_error) as e:
            self.log_error(f"Error getting installed software: {str(e)}", e)
            return []

    def _read_file_via_wmi(self, path: str) -> Optional[str]:
        """
        Legge il contenuto di un file tramite WMI.

        Args:
            path: Percorso del file da leggere

        Returns:
            Contenuto del file o None in caso di errore
        """
        if not self.is_connected() and not self.connect():
            return None

        try:
            self.log_debug(f"Reading file content: {path}")

            # Verifica se il file esiste
            if not self.check_file_exists(path):
                self.log_debug(f"File not found: {path}")
                return None

            # Per leggere il file, dobbiamo usare un approccio indiretto
            # Usiamo un comando per scrivere il contenuto in base64 e poi lo decodifichiamo

            # Generiamo un nome file temporaneo univoco per l'output in base64
            timestamp = int(time.time())
            base64_file = f"C:\\Windows\\Temp\\wmi_b64_{timestamp}.txt"

            # Esegui il comando per codificare il file in base64
            cmd_result = self.execute_command(
                f'powershell -Command "[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes(\'{path}\'))" > {base64_file}'
            )

            if cmd_result['exit_code'] != 0:
                self.log_error(f"Error reading file: {cmd_result['stderr']}")
                return None

            # Ora leggiamo il file base64 (che possiamo leggere direttamente con WMI)
            # Normalizza il percorso per WMI (usa \\ invece di \)
            b64_path = base64_file.replace('\\', '\\\\')

            # Usa CIM_DataFile per leggere il file
            files = self.conn.query(f"SELECT * FROM CIM_DataFile WHERE Name = '{b64_path}'")

            if len(files) == 0:
                self.log_error(f"Base64 file not found: {base64_file}")
                return None

            # Leggi il contenuto del file base64
            import base64
            import binascii

            try:
                # Usa il metodo alternativo per leggere il file
                # Esegui un comando per leggere il file e restituirlo
                cat_result = self.execute_command(f'type {base64_file}')

                if cat_result['exit_code'] != 0:
                    self.log_error(f"Error reading base64 file: {cat_result['stderr']}")
                    return None

                # Decodifica il contenuto base64
                b64_content = cat_result['stdout'].strip()
                try:
                    # Tenta la decodifica
                    decoded_content = base64.b64decode(b64_content).decode('utf-8', errors='replace')
                    return decoded_content
                except (binascii.Error, UnicodeDecodeError) as e:
                    self.log_error(f"Error decoding base64 content: {str(e)}")
                    return None

            finally:
                # Pulisci il file temporaneo
                self._delete_file_via_wmi(base64_file)

        except (wmi.x_wmi, pythoncom.com_error) as e:
            self.log_error(f"Error reading file via WMI: {str(e)}", e)
            return None

    def _delete_file_via_wmi(self, path: str) -> bool:
        """
        Elimina un file tramite WMI.

        Args:
            path: Percorso del file da eliminare

        Returns:
            True se l'eliminazione ha successo, False altrimenti
        """
        if not self.is_connected() and not self.connect():
            return False

        try:
            self.log_debug(f"Deleting file: {path}")

            # Esegui un comando per eliminare il file
            del_result = self.execute_command(f'del /q /f "{path}"')

            return del_result['exit_code'] == 0

        except (wmi.x_wmi, pythoncom.com_error) as e:
            self.log_error(f"Error deleting file via WMI: {str(e)}", e)
            return False