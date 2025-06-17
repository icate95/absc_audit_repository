"""
Logging Checks - Implementazione dei controlli di logging ABSC 10.x.

Questo modulo implementa i controlli relativi al logging degli eventi
secondo le specifiche ABSC 10.x.
"""

import time
import re
import os
import datetime
from typing import Dict, List, Optional, Any, Tuple

from absc_audit.checks.base import BaseCheck
from absc_audit.storage.models import Target
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class LoggingConfigurationCheck(BaseCheck):
    """
    Controllo per verificare la configurazione del logging (ABSC 10.1.1-10.1.2).

    Verifica se è implementata una corretta gestione dei log con conservazione per un periodo adeguato.
    """

    ID = "10.1.1-10.1.2"
    NAME = "Configurazione del logging"
    DESCRIPTION = "Verifica della configurazione del logging e della conservazione dei log"
    QUESTION = "È implementata una corretta gestione dei log con conservazione per un periodo adeguato?"
    POSSIBLE_ANSWERS = ["Sì completo", "Sì parziale", "No"]
    CATEGORY = "Logging"
    PRIORITY = 3  # Bassa priorità

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Esegue il controllo sulla configurazione del logging.

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

            # 1. Verifica la configurazione del logging di sistema
            system_logging = self._check_system_logging(target)

            # 2. Verifica la configurazione del logging per servizi critici
            service_logging = self._check_service_logging(target)

            # 3. Verifica la rotazione e conservazione dei log
            log_retention = self._check_log_retention(target)

            # Compila i risultati
            result['raw_data'] = {
                'system_logging': system_logging,
                'service_logging': service_logging,
                'log_retention': log_retention
            }

            # Determina lo stato
            if system_logging['implemented'] and service_logging['implemented'] and log_retention['implemented']:
                result['status'] = "Sì completo"
            elif (system_logging['implemented'] and (
                    service_logging['implemented'] or log_retention['implemented'])) or (
                    service_logging['implemented'] and log_retention['implemented']):
                result['status'] = "Sì parziale"
            else:
                result['status'] = "No"

            # Calcola punteggio
            result['score'] = self._calculate_custom_score(result['status'])

            # Aggiungi dettagli
            result['details'] = {
                'has_system_logging': system_logging['implemented'],
                'has_service_logging': service_logging['implemented'],
                'has_log_retention': log_retention['implemented'],
                'system_logging_details': system_logging,
                'service_logging_details': service_logging,
                'log_retention_details': log_retention
            }

            # Aggiungi note
            if result['status'] == "No":
                result[
                    'notes'] = "Non è stata trovata una corretta configurazione del logging. È necessario implementare un sistema di logging completo con conservazione adeguata."
            elif result['status'] == "Sì parziale":
                result[
                    'notes'] = "Sono implementati alcuni aspetti della gestione dei log, ma la configurazione non è completa. Si consiglia di migliorare gli aspetti mancanti."
            else:
                result[
                    'notes'] = "È implementata una configurazione completa del logging con corretta gestione e conservazione dei log."

        except Exception as e:
            self.log_error(target, e)
            result['status'] = "ERROR"
            result['details'] = {'error': str(e)}
            result['score'] = 0
        finally:
            duration = time.time() - start_time
            self.log_check_end(target, result['status'], duration)

        return result

    def _check_system_logging(self, target: Target) -> Dict:
        """
        Verifica la configurazione del logging di sistema.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sul logging di sistema
        """
        sys_logging = {
            'implemented': False,
            'syslog_configured': False,
            'eventlog_configured': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica servizio syslog
            syslog_services = ['rsyslog', 'syslog-ng', 'syslogd']
            for service in syslog_services:
                status = self.check_service_status(target, service)
                if status.get('running', False):
                    sys_logging['syslog_configured'] = True
                    sys_logging['implemented'] = True
                    sys_logging['details'].append(f"Servizio {service} attivo")

            # Verifica configurazione rsyslog
            config_paths = [
                '/etc/rsyslog.conf',
                '/etc/syslog-ng/syslog-ng.conf',
                '/etc/syslog.conf'
            ]
            for path in config_paths:
                if self.check_file_exists(target, path):
                    content = self.read_file_content(target, path)
                    if content:
                        sys_logging['details'].append(f"Configurazione logging trovata in {path}")

                        # Verifica logging remoto
                        if re.search(r'@\d', content) or '@(' in content:
                            sys_logging['details'].append("Logging remoto configurato")

                        # Verifica livelli di logging
                        if re.search(r'\.info|\.notice|\.warning|\.err|\.crit|\.alert|\.emerg', content):
                            sys_logging['details'].append("Livelli di logging configurati")

            # Verifica esistenza e dimensione file di log
            log_files = [
                '/var/log/syslog',
                '/var/log/messages',
                '/var/log/secure',
                '/var/log/auth.log'
            ]
            log_files_found = 0

            for log_file in log_files:
                if self.check_file_exists(target, log_file):
                    log_files_found += 1
                    cmd = f"du -h {log_file} | cut -f1"
                    result = self.execute_command(target, cmd)

                    if result['exit_code'] == 0 and result['stdout'].strip():
                        sys_logging['details'].append(
                            f"File di log {log_file} trovato, dimensione: {result['stdout'].strip()}")

            if log_files_found > 0:
                sys_logging['syslog_configured'] = True
                sys_logging['implemented'] = True

            # Verifica journald su sistemi con systemd
            cmd = "which journalctl 2>/dev/null || command -v journalctl 2>/dev/null"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                sys_logging['implemented'] = True
                sys_logging['details'].append("systemd journald attivo")

                # Verifica configurazione journald
                journald_conf = self.read_file_content(target, '/etc/systemd/journald.conf')
                if journald_conf:
                    sys_logging['details'].append("Configurazione journald trovata")

                    # Verifica persistenza
                    if re.search(r'Storage\s*=\s*persistent', journald_conf):
                        sys_logging['details'].append("journald configurato per archiviazione persistente")

        elif target.os_type.lower() == 'windows':
            # Verifica Event Log
            cmd = 'powershell -Command "Get-Service -Name EventLog | Where-Object { $_.Status -eq \'Running\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                sys_logging['eventlog_configured'] = True
                sys_logging['implemented'] = True
                sys_logging['details'].append("Windows Event Log attivo")

                # Verifica dimensione e criteri di conservazione
                cmd = 'powershell -Command "Get-WinEvent -ListLog Application,System,Security | Select-Object LogName,MaximumSizeInBytes,LogMode | Format-List"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    sys_logging['details'].append("Configurazione Event Log:")

                    # Verifica dimensione dei log (sono adeguati?)
                    if re.search(r'MaximumSizeInBytes\s*:\s*(\d+)', result['stdout']):
                        for match in re.finditer(r'LogName\s*:\s*(\w+)\s*\n.*?MaximumSizeInBytes\s*:\s*(\d+)',
                                                 result['stdout'], re.DOTALL):
                            log_name = match.group(1)
                            size_bytes = int(match.group(2))
                            size_mb = size_bytes / (1024 * 1024)

                            if size_mb >= 100:  # Consideriamo adeguato se almeno 100 MB
                                sys_logging['details'].append(
                                    f"Log {log_name} ha dimensione adeguata: {size_mb:.2f} MB")
                            else:
                                sys_logging['details'].append(
                                    f"Log {log_name} ha dimensione limitata: {size_mb:.2f} MB")

                    # Verifica modalità di conservazione
                    if re.search(r'LogMode\s*:\s*(\w+)', result['stdout']):
                        log_modes = re.findall(r'LogMode\s*:\s*(\w+)', result['stdout'])
                        circular_count = log_modes.count('Circular')
                        archive_count = log_modes.count('AutoBackup')

                        if circular_count > 0:
                            sys_logging['details'].append(f"{circular_count} log configurati in modalità circolare")
                        if archive_count > 0:
                            sys_logging['details'].append(f"{archive_count} log configurati per backup automatico")

            # Verifica log di sicurezza
            cmd = 'powershell -Command "Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                sys_logging['details'].append("Log di sicurezza attivi")

            # Verifica policy di audit
            cmd = 'powershell -Command "auditpol /get /category:* | Select-String Success | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and int(result['stdout'].strip()) > 5:  # Se almeno 5 categorie sono auditate
                sys_logging['details'].append("Policy di audit configurate")

        return sys_logging

    def _check_service_logging(self, target: Target) -> Dict:
        """
        Verifica la configurazione del logging per servizi critici.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sul logging dei servizi
        """
        service_logging = {
            'implemented': False,
            'web_server_logging': False,
            'database_logging': False,
            'ssh_logging': False,
            'firewall_logging': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica logging web server
            web_servers = ['apache2', 'httpd', 'nginx']
            for server in web_servers:
                if self.check_process_running(target, server):
                    log_paths = []
                    if server in ['apache2', 'httpd']:
                        log_paths = ['/var/log/apache2', '/var/log/httpd']
                    elif server == 'nginx':
                        log_paths = ['/var/log/nginx']

                    for path in log_paths:
                        if self.check_file_exists(target, path):
                            service_logging['web_server_logging'] = True
                            service_logging['implemented'] = True

                            # Verifica presenza e dimensione dei log
                            cmd = f"find {path} -name '*.log' -mtime -7 | wc -l"
                            result = self.execute_command(target, cmd)

                            if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                                service_logging['details'].append(
                                    f"Logging attivo per {server}, {result['stdout'].strip()} file di log recenti")

            # Verifica logging database
            db_servers = [
                {'name': 'mysql', 'log_paths': ['/var/log/mysql', '/var/lib/mysql/*.log']},
                {'name': 'mariadb', 'log_paths': ['/var/log/mariadb', '/var/lib/mysql/*.log']},
                {'name': 'postgresql', 'log_paths': ['/var/log/postgresql']}
            ]

            for db in db_servers:
                if self.check_process_running(target, db['name']):
                    for path in db['log_paths']:
                        cmd = f"find {path} -type f 2>/dev/null | head -1"
                        result = self.execute_command(target, cmd)

                        if result['exit_code'] == 0 and result['stdout'].strip():
                            service_logging['database_logging'] = True
                            service_logging['implemented'] = True
                            service_logging['details'].append(f"Logging attivo per {db['name']}")

            # Verifica logging SSH
            if self.check_process_running(target, 'sshd'):
                # SSH generalmente logga in syslog
                cmd = "grep -l sshd /var/log/* 2>/dev/null | head -3"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    service_logging['ssh_logging'] = True
                    service_logging['implemented'] = True
                    service_logging['details'].append(f"Logging SSH trovato in: {result['stdout'].strip()}")

            # Verifica logging firewall
            fw_logs = ['/var/log/iptables', '/var/log/ufw.log', '/var/log/firewalld']
            for log in fw_logs:
                if self.check_file_exists(target, log):
                    service_logging['firewall_logging'] = True
                    service_logging['implemented'] = True
                    service_logging['details'].append(f"Logging firewall trovato in {log}")

            # Controlla anche log di sistema per eventi firewall
            cmd = "grep -l 'iptables\\|firewall\\|ufw\\|DROP\\|REJECT' /var/log/* 2>/dev/null | head -3"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                service_logging['firewall_logging'] = True
                service_logging['implemented'] = True
                service_logging['details'].append(f"Eventi firewall nei log di sistema: {result['stdout'].strip()}")

        elif target.os_type.lower() == 'windows':
            # Verifica logging IIS
            cmd = 'powershell -Command "Get-Service -Name W3SVC -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq \'Running\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                # Controlla log IIS
                cmd = 'powershell -Command "Get-Item -Path \'C:\\inetpub\\logs\\LogFiles\\W3SVC*\' -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                    service_logging['web_server_logging'] = True
                    service_logging['implemented'] = True
                    service_logging['details'].append("Logging IIS attivo")

            # Verifica logging SQL Server
            cmd = 'powershell -Command "Get-Service -Name MSSQLSERVER -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq \'Running\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                # SQL Server è in esecuzione, controlla se il logging è attivo
                cmd = 'powershell -Command "Get-Item -Path \'C:\\Program Files\\Microsoft SQL Server\\*\\MSSQL\\Log\\ERRORLOG*\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                    service_logging['database_logging'] = True
                    service_logging['implemented'] = True
                    service_logging['details'].append("Logging SQL Server attivo")

            # Verifica logging RDP
            cmd = 'powershell -Command "Get-WinEvent -LogName \'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational\' -MaxEvents 1 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                service_logging['ssh_logging'] = True  # Usiamo ssh_logging anche per RDP
                service_logging['implemented'] = True
                service_logging['details'].append("Logging RDP attivo")

            # Verifica logging firewall
            cmd = 'powershell -Command "Get-WinEvent -LogName \'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall\' -MaxEvents 1 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                service_logging['firewall_logging'] = True
                service_logging['implemented'] = True
                service_logging['details'].append("Logging Windows Firewall attivo")

            # Controlla anche configurazione esplicita del logging del firewall
            cmd = 'powershell -Command "Get-NetFirewallProfile | Select-Object -ExpandProperty LogAllowed"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and 'True' in result['stdout']:
                service_logging['firewall_logging'] = True
                service_logging['implemented'] = True
                service_logging['details'].append("Logging connessioni permesse nel firewall configurato")

        return service_logging

    def _check_log_retention(self, target: Target) -> Dict:
        """
        Verifica la rotazione e conservazione dei log.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulla conservazione dei log
        """
        retention = {
            'implemented': False,
            'log_rotation_configured': False,
            'retention_period_adequate': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica configurazione logrotate
            logrotate_paths = [
                '/etc/logrotate.conf',
                '/etc/logrotate.d'
            ]

            for path in logrotate_paths:
                if self.check_file_exists(target, path):
                    retention['log_rotation_configured'] = True

                    # Se è una directory, controlla i file all'interno
                    if path.endswith('/d'):
                        cmd = f"find {path} -type f | head -5"
                        result = self.execute_command(target, cmd)

                        if result['exit_code'] == 0 and result['stdout'].strip():
                            files_count = len(result['stdout'].strip().split('\n'))
                            retention['details'].append(f"Trovate {files_count} configurazioni logrotate")
                    else:
                        # Controlla periodo di conservazione nei file di configurazione
                        content = self.read_file_content(target, path)
                        if content:
                            # Cerca direttive di rotazione
                            rotate_matches = re.findall(r'rotate\s+(\d+)', content)
                            if rotate_matches:
                                max_rotate = max(map(int, rotate_matches))
                                retention['details'].append(f"Periodo massimo di conservazione: {max_rotate} rotazioni")

                                # Se il periodo è adeguato (almeno 52 = 1 anno con rotazione settimanale)
                                if max_rotate >= 52:
                                    retention['retention_period_adequate'] = True

                            # Cerca direttive di frequenza
                            if re.search(r'daily|weekly|monthly', content):
                                retention['details'].append(f"Frequenza di rotazione configurata")

            # Controlla anzianità dei log
            cmd = "find /var/log -name '*.gz' -o -name '*.1' -o -name '*.old' | wc -l"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and int(
                    result['stdout'].strip()) > 10:  # Assumiamo che >10 log rotati sia un buon segno
                retention['details'].append(f"Trovati {result['stdout'].strip()} file di log rotati")
                retention['log_rotation_configured'] = True

            # Controlla anzianità del log più vecchio
            cmd = "find /var/log -name '*.gz' -o -name '*.old' -type f -printf '%T@ %p\\n' 2>/dev/null | sort -n | head -1"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                # Estrai timestamp e calcola età in giorni
                parts = result['stdout'].strip().split(' ', 1)
                if len(parts) >= 1:
                    try:
                        oldest_ts = float(parts[0])
                        age_days = (time.time() - oldest_ts) / (60 * 60 * 24)

                        retention['details'].append(f"Log più vecchio ha {int(age_days)} giorni")

                        # Considera adeguato se ha almeno 180 giorni (6 mesi)
                        if age_days >= 180:
                            retention['retention_period_adequate'] = True
                    except (ValueError, IndexError):
                        pass

            # Determina implementazione
            if retention['log_rotation_configured'] and retention['retention_period_adequate']:
                retention['implemented'] = True

        elif target.os_type.lower() == 'windows':
            # Verifica configurazione Event Log
            cmd = 'powershell -Command "Get-WinEvent -ListLog Application,System,Security | Select-Object LogName,MaximumSizeInBytes,LogMode | Format-List"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                retention['log_rotation_configured'] = True

                # Verifica modalità di conservazione
                if re.search(r'LogMode\s*:\s*(\w+)', result['stdout']):
                    log_modes = re.findall(r'LogMode\s*:\s*(\w+)', result['stdout'])
                    archive_count = log_modes.count('AutoBackup')

                    if archive_count > 0:
                        retention['details'].append(f"{archive_count} log configurati per backup automatico")
                        retention['retention_period_adequate'] = True

            # Verifica presenza di backup dei log
            cmd = 'powershell -Command "Get-Item -Path \'C:\\Windows\\System32\\winevt\\Logs\\*.evtx\' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and int(
                    result['stdout'].strip()) > 10:  # Assumiamo che >10 file di log sia un buon segno
                retention['details'].append(f"Trovati {result['stdout'].strip()} file di log")
                retention['log_rotation_configured'] = True

            # Controlla policy di conservazione configurate negli eventi di sistema
            cmd = 'powershell -Command "Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\*\' -Name Retention -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                retention['details'].append("Policy di conservazione configurate nel registro")
                retention['retention_period_adequate'] = True

            # Verifica età del log più vecchio
            cmd = 'powershell -Command "Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 } | ForEach-Object { Get-WinEvent -LogName $_.LogName -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue } | Sort-Object TimeCreated | Select-Object -First 1 | Select-Object -ExpandProperty TimeCreated"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                try:
                    # Converte la data e calcola l'età in giorni
                    oldest_date = datetime.datetime.strptime(result['stdout'].strip(), '%m/%d/%Y %I:%M:%S %p')
                    age_days = (datetime.datetime.now() - oldest_date).days

                    retention['details'].append(f"Log più vecchio ha {age_days} giorni")

                    # Considera adeguato se ha almeno 180 giorni (6 mesi)
                    if age_days >= 180:
                        retention['retention_period_adequate'] = True
                except (ValueError, TypeError):
                    pass

            # Determina implementazione
            if retention['log_rotation_configured'] and retention['retention_period_adequate']:
                retention['implemented'] = True

        return retention

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
        elif status == "Sì parziale":
            return 60
        elif status == "No":
            return 0
        else:
            return 0


class LogReviewCheck(BaseCheck):
    """
    Controllo per verificare il processo di analisi dei log (ABSC 10.3.1-10.3.2).

    Verifica se è implementato un processo di analisi dei log per individuare anomalie o attività sospette.
    """

    ID = "10.3.1-10.3.2"
    NAME = "Analisi dei log"
    DESCRIPTION = "Verifica del processo di analisi dei log per individuare anomalie"
    QUESTION = "È implementato un processo di analisi dei log per individuare anomalie o attività sospette?"
    POSSIBLE_ANSWERS = ["Sì automatizzato", "Sì manuale", "No"]
    CATEGORY = "Logging"
    PRIORITY = 3  # Bassa priorità

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Esegue il controllo sul processo di analisi dei log.

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

            # 1. Verifica la presenza di strumenti automatici di analisi
            automated_analysis = self._check_automated_analysis(target)

            # 2. Verifica la presenza di processi manuali di analisi
            manual_analysis = self._check_manual_analysis(target)

            # 3. Verifica la generazione di allarmi o notifiche
            alerting = self._check_alerting(target)

            # Compila i risultati
            result['raw_data'] = {
                'automated_analysis': automated_analysis,
                'manual_analysis': manual_analysis,
                'alerting': alerting
            }

            # Determina lo stato
            if automated_analysis['implemented'] and alerting['implemented']:
                result['status'] = "Sì automatizzato"
            elif manual_analysis['implemented']:
                result['status'] = "Sì manuale"
            else:
                result['status'] = "No"

            # Calcola punteggio
            result['score'] = self._calculate_custom_score(result['status'])

            # Aggiungi dettagli
            result['details'] = {
                'has_automated_analysis': automated_analysis['implemented'],
                'has_automated_analysis': automated_analysis['implemented'],
                'has_manual_analysis': manual_analysis['implemented'],
                'has_alerting': alerting['implemented'],
                'automated_analysis_details': automated_analysis,
                'manual_analysis_details': manual_analysis,
                'alerting_details': alerting
            }

            # Aggiungi note
            if result['status'] == "No":
                result[
                    'notes'] = "Non è stato trovato un processo di analisi dei log. È necessario implementare un sistema di monitoraggio e analisi dei log per individuare anomalie."
            elif result['status'] == "Sì manuale":
                result[
                    'notes'] = "È implementato un processo manuale di analisi dei log. Si consiglia di implementare strumenti automatici per migliorare l'efficacia dell'analisi."
            else:
                result[
                    'notes'] = "È implementato un processo automatizzato di analisi dei log con generazione di allarmi per identificare tempestivamente anomalie e attività sospette."

        except Exception as e:
            self.log_error(target, e)
            result['status'] = "ERROR"
            result['details'] = {'error': str(e)}
            result['score'] = 0
        finally:
            duration = time.time() - start_time
            self.log_check_end(target, result['status'], duration)

        return result

    def _check_automated_analysis(self, target: Target) -> Dict:
        """
        Verifica la presenza di strumenti automatici di analisi dei log.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sull'analisi automatica
        """
        auto_analysis = {
            'implemented': False,
            'siem_present': False,
            'log_analysis_tools': [],
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Cerca software SIEM/log analysis comuni
            siem_tools = [
                {'name': 'Elasticsearch', 'process': 'elasticsearch', 'path': '/etc/elasticsearch'},
                {'name': 'Logstash', 'process': 'logstash', 'path': '/etc/logstash'},
                {'name': 'Kibana', 'process': 'kibana', 'path': '/etc/kibana'},
                {'name': 'Graylog', 'process': 'graylog-server', 'path': '/etc/graylog'},
                {'name': 'Splunk', 'process': 'splunkd', 'path': '/opt/splunk'},
                {'name': 'Wazuh', 'process': 'wazuh', 'path': '/var/ossec'},
                {'name': 'OSSEC', 'process': 'ossec', 'path': '/var/ossec'},
                {'name': 'Nagios', 'process': 'nagios', 'path': '/etc/nagios'},
                {'name': 'Zabbix', 'process': 'zabbix', 'path': '/etc/zabbix'}
            ]

            for tool in siem_tools:
                # Controlla processo
                if self.check_process_running(target, tool['process']):
                    auto_analysis['log_analysis_tools'].append(tool['name'])
                    auto_analysis['implemented'] = True
                    auto_analysis['details'].append(f"{tool['name']} trovato in esecuzione")

                    # Se è un vero SIEM, non solo monitoring
                    if tool['name'] in ['Elasticsearch', 'Splunk', 'Graylog', 'Wazuh', 'OSSEC']:
                        auto_analysis['siem_present'] = True

                # Controlla directory di installazione
                elif self.check_file_exists(target, tool['path']):
                    auto_analysis['log_analysis_tools'].append(tool['name'])
                    auto_analysis['details'].append(f"{tool['name']} trovato installato in {tool['path']}")

                    # Se è un vero SIEM, non solo monitoring
                    if tool['name'] in ['Elasticsearch', 'Splunk', 'Graylog', 'Wazuh', 'OSSEC']:
                        auto_analysis['siem_present'] = True
                        auto_analysis['implemented'] = True

            # Cerca script di analisi log
            script_paths = [
                '/usr/local/bin/log-analyzer.sh',
                '/usr/local/bin/analyze-logs.py',
                '/opt/scripts/log-analysis.py',
                '/etc/cron.daily/analyze-logs'
            ]

            for path in script_paths:
                if self.check_file_exists(target, path):
                    content = self.read_file_content(target, path)
                    if content and re.search(r'grep|awk|sed|error|warning|suspicious|alert', content, re.IGNORECASE):
                        auto_analysis['log_analysis_tools'].append('Custom script')
                        auto_analysis['implemented'] = True
                        auto_analysis['details'].append(f"Script di analisi log trovato in {path}")

            # Controlla job cron per analisi log
            cmd = "grep -r 'log\\|alert\\|analyze' /etc/cron* 2>/dev/null"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                auto_analysis['log_analysis_tools'].append('Cron job')
                auto_analysis['implemented'] = True
                auto_analysis['details'].append("Job cron per analisi log trovati")

        elif target.os_type.lower() == 'windows':
            # Cerca software SIEM/log analysis comuni su Windows
            siem_tools = [
                'Splunk',
                'LogRhythm',
                'ArcSight',
                'QRadar',
                'Elastic',
                'Wazuh',
                'OSSEC',
                'EventSentry',
                'Nagios',
                'Zabbix'
            ]

            for tool in siem_tools:
                cmd = f'powershell -Command "Get-ItemProperty HKLM:\\Software\\*\\*, HKLM:\\Software\\Wow6432Node\\*\\* | Where-Object {{ $_.DisplayName -match \'{tool}\' }} | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    auto_analysis['log_analysis_tools'].append(tool)
                    auto_analysis['implemented'] = True
                    auto_analysis['details'].append(f"{tool} trovato installato")

                    # Se è un vero SIEM, non solo monitoring
                    if tool in ['Splunk', 'LogRhythm', 'ArcSight', 'QRadar', 'Elastic', 'Wazuh', 'OSSEC']:
                        auto_analysis['siem_present'] = True

            # Verifica servizi correlati
            siem_services = [
                'Splunkd',
                'LogRhythm',
                'ArcSight',
                'QRadar',
                'elasticsearch-service',
                'Wazuh',
                'OssecSvc',
                'EventSentry'
            ]

            for service in siem_services:
                cmd = f'powershell -Command "Get-Service -Name {service}* -ErrorAction SilentlyContinue | Where-Object {{ $_.Status -eq \'Running\' }} | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    if service not in auto_analysis['log_analysis_tools']:
                        auto_analysis['log_analysis_tools'].append(service)
                        auto_analysis['implemented'] = True
                        auto_analysis['details'].append(f"Servizio {service} trovato in esecuzione")

                        # Se è un vero SIEM, non solo monitoring
                        if service in ['Splunkd', 'LogRhythm', 'ArcSight', 'QRadar', 'elasticsearch-service', 'Wazuh',
                                       'OssecSvc']:
                            auto_analysis['siem_present'] = True

            # Cerca script PowerShell di analisi log
            script_paths = [
                'C:\\Scripts\\LogAnalysis.ps1',
                'C:\\Program Files\\LogAnalysis\\',
                'C:\\ProgramData\\LogAnalysis\\'
            ]

            for path in script_paths:
                cmd = f'powershell -Command "Test-Path \'{path}\'"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip().lower() == 'true':
                    # Se è una directory, cerca file .ps1 al suo interno
                    if path.endswith('\\'):
                        cmd = f'powershell -Command "Get-ChildItem -Path \'{path}\' -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
                        result = self.execute_command(target, cmd)

                        if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                            auto_analysis['log_analysis_tools'].append('PowerShell scripts')
                            auto_analysis['implemented'] = True
                            auto_analysis['details'].append(f"Script PowerShell di analisi log trovati in {path}")
                    else:
                        auto_analysis['log_analysis_tools'].append('PowerShell script')
                        auto_analysis['implemented'] = True
                        auto_analysis['details'].append(f"Script PowerShell di analisi log trovato in {path}")

            # Verifica task pianificati per analisi log
            cmd = 'powershell -Command "Get-ScheduledTask -TaskName *log*,*event*,*analyze* -ErrorAction SilentlyContinue | Where-Object { $_.State -eq \'Ready\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                auto_analysis['log_analysis_tools'].append('Scheduled tasks')
                auto_analysis['implemented'] = True
                auto_analysis['details'].append("Task pianificati per analisi log trovati")

        return auto_analysis

    def _check_manual_analysis(self, target: Target) -> Dict:
        """
        Verifica la presenza di processi manuali di analisi dei log.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sull'analisi manuale
        """
        manual_analysis = {
            'implemented': False,
            'documentation_found': False,
            'log_viewers_present': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Cerca documentazione di procedure manuali
            doc_paths = [
                '/etc/log-review-procedure.txt',
                '/etc/log-review-procedure.md',
                '/usr/local/share/doc/log-analysis/',
                '/opt/log-analysis/docs/'
            ]

            for path in doc_paths:
                if self.check_file_exists(target, path):
                    manual_analysis['documentation_found'] = True
                    manual_analysis['implemented'] = True
                    manual_analysis['details'].append(f"Documentazione di analisi log trovata in {path}")

            # Cerca script/tool per visualizzazione dei log
            log_tools = ['lnav', 'multitail', 'logtail', 'glogg']
            for tool in log_tools:
                cmd = f"which {tool} 2>/dev/null || command -v {tool} 2>/dev/null"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    manual_analysis['log_viewers_present'] = True
                    manual_analysis['implemented'] = True
                    manual_analysis['details'].append(f"Tool di visualizzazione log trovato: {tool}")

            # Controlla se ci sono script di estrazione/report log
            script_paths = [
                '/usr/local/bin/log-report.sh',
                '/usr/local/bin/daily-log-review.sh',
                '/opt/scripts/log-summary.py'
            ]

            for path in script_paths:
                if self.check_file_exists(target, path):
                    manual_analysis['implemented'] = True
                    manual_analysis['details'].append(f"Script di report log trovato in {path}")

        elif target.os_type.lower() == 'windows':
            # Cerca documentazione di procedure manuali
            doc_paths = [
                'C:\\LogAnalysis\\Procedures.docx',
                'C:\\LogAnalysis\\Procedures.txt',
                'C:\\ProgramData\\LogAnalysis\\Docs\\'
            ]

            for path in doc_paths:
                cmd = f'powershell -Command "Test-Path \'{path}\'"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip().lower() == 'true':
                    manual_analysis['documentation_found'] = True
                    manual_analysis['implemented'] = True
                    manual_analysis['details'].append(f"Documentazione di analisi log trovata in {path}")

            # Cerca software di visualizzazione log
            log_viewers = ['BareTail', 'LogExpert', 'LogFusion', 'Event Log Explorer']
            for viewer in log_viewers:
                cmd = f'powershell -Command "Get-ItemProperty HKLM:\\Software\\*\\*, HKLM:\\Software\\Wow6432Node\\*\\* | Where-Object {{ $_.DisplayName -match \'{viewer}\' }} | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    manual_analysis['log_viewers_present'] = True
                    manual_analysis['implemented'] = True
                    manual_analysis['details'].append(f"Visualizzatore di log trovato: {viewer}")

            # Controlla script per report/estrazione dei log
            script_paths = [
                'C:\\Scripts\\LogReport.ps1',
                'C:\\Scripts\\DailyLogReview.ps1',
                'C:\\ProgramData\\LogAnalysis\\reports.ps1'
            ]

            for path in script_paths:
                cmd = f'powershell -Command "Test-Path \'{path}\'"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip().lower() == 'true':
                    manual_analysis['implemented'] = True
                    manual_analysis['details'].append(f"Script di report log trovato in {path}")

        return manual_analysis

    def _check_alerting(self, target: Target) -> Dict:
        """
        Verifica la generazione di allarmi o notifiche.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulla generazione di allarmi
        """
        alerting = {
            'implemented': False,
            'email_alerts': False,
            'sms_alerts': False,
            'dashboard_alerts': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Cerca configurazioni di posta per allarmi
            mail_configs = [
                '/etc/aliases',  # Cerca forward a admin/security
                '/etc/postfix/main.cf',
                '/etc/mail/sendmail.cf'
            ]

            for config in mail_configs:
                content = self.read_file_content(target, config)
                if content and re.search(r'alert|notify|security|admin', content, re.IGNORECASE):
                    alerting['email_alerts'] = True
                    alerting['implemented'] = True
                    alerting['details'].append(f"Configurazione email per allarmi trovata in {config}")

            # Cerca script di notifica
            alert_scripts = [
                '/usr/local/bin/send-alert.sh',
                '/usr/local/bin/notify-admin.py',
                '/opt/scripts/security-alert.sh'
            ]

            for script in alert_scripts:
                if self.check_file_exists(target, script):
                    content = self.read_file_content(target, script)
                    if content:
                        alerting['implemented'] = True
                        alerting['details'].append(f"Script di notifica trovato in {script}")

                        # Controlla tipo di notifica
                        if 'mail' in content or 'sendmail' in content or 'smtp' in content:
                            alerting['email_alerts'] = True
                            alerting['details'].append("Notifiche email configurate")

                        if 'sms' in content or 'twilio' in content or 'message' in content:
                            alerting['sms_alerts'] = True
                            alerting['details'].append("Notifiche SMS configurate")

            # Cerca software di dashboard/alerting
            dashboard_tools = ['grafana', 'kibana', 'nagios', 'zabbix', 'prometheus']
            for tool in dashboard_tools:
                if self.check_process_running(target, tool):
                    alerting['dashboard_alerts'] = True
                    alerting['implemented'] = True
                    alerting['details'].append(f"Dashboard {tool} trovata in esecuzione")

        elif target.os_type.lower() == 'windows':
            # Controlla configurazione di Event Subscription/Forwarding
            cmd = 'powershell -Command "Get-WinEvent -ListLog Microsoft-Windows-EventCollector/Operational -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                alerting['implemented'] = True
                alerting['details'].append("Event Collection/Forwarding configurato")

            # Controlla Scheduled Tasks che inviano alert
            cmd = 'powershell -Command "Get-ScheduledTask -TaskName *alert*,*notify*,*email* -ErrorAction SilentlyContinue | Where-Object { $_.State -eq \'Ready\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                alerting['implemented'] = True
                alerting['details'].append(f"Trovati {result['stdout'].strip()} task pianificati per notifiche")

            # Cerca script PowerShell di notifica
            script_paths = [
                'C:\\Scripts\\SendAlert.ps1',
                'C:\\Scripts\\NotifyAdmin.ps1',
                'C:\\ProgramData\\AlertScripts\\'
            ]

            for path in script_paths:
                cmd = f'powershell -Command "Test-Path \'{path}\'"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip().lower() == 'true':
                    if not path.endswith('\\'):
                        # È un file, leggi il contenuto
                        content = self.read_file_content(target, path)
                        if content:
                            alerting['implemented'] = True
                            alerting['details'].append(f"Script di notifica trovato in {path}")

                            # Controlla tipo di notifica
                            if 'smtp' in content.lower() or 'send-mailmessage' in content.lower():
                                alerting['email_alerts'] = True
                                alerting['details'].append("Notifiche email configurate")
                    else:
                        # È una directory, cerca script all'interno
                        cmd = f'powershell -Command "Get-ChildItem -Path \'{path}\' -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern \'smtp|email|send-mailmessage|alert|notify\' | Measure-Object | Select-Object -ExpandProperty Count"'
                        result = self.execute_command(target, cmd)

                        if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                            alerting['implemented'] = True
                            alerting['email_alerts'] = True
                            alerting['details'].append(f"Script di notifica email trovati in {path}")

            # Cerca software di dashboard/alerting
            dashboard_tools = ['Grafana', 'Kibana', 'Nagios', 'Zabbix', 'PRTG', 'SolarWinds']
            for tool in dashboard_tools:
                cmd = f'powershell -Command "Get-Process -Name *{tool}* -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    alerting['dashboard_alerts'] = True
                    alerting['implemented'] = True
                    alerting['details'].append(f"Dashboard {tool} trovata in esecuzione")

        return alerting

    def _calculate_custom_score(self, status: str) -> float:
        """
        Calcola un punteggio personalizzato in base allo stato.

        Args:
            status: Stato del controllo

        Returns:
            Punteggio da 0 a 100
        """
        if status == "Sì automatizzato":
            return 100
        elif status == "Sì manuale":
            return 60
        elif status == "No":
            return 0
        else:
            return 0