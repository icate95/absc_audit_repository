"""
Backup Checks - Implementazione dei controlli di backup ABSC 13.x.

Questo modulo implementa i controlli relativi alle procedure di backup e
ripristino secondo le specifiche ABSC 13.x.
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


class BackupProcedureCheck(BaseCheck):
    """
    Controllo per verificare l'implementazione di procedure di backup (ABSC 13.1.1-13.1.3).

    Verifica se sono implementate procedure di backup regolari e complete.
    """

    ID = "13.1.1-13.1.3"
    NAME = "Procedure di backup"
    DESCRIPTION = "Verifica dell'implementazione di procedure di backup regolari e complete"
    QUESTION = "Sono implementate procedure di backup regolari e complete per il ripristino dei dati e del sistema?"
    POSSIBLE_ANSWERS = ["Sì completo", "Sì solo dati", "Sì solo sistema", "No"]
    CATEGORY = "Backup"
    PRIORITY = 2  # Media priorità

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Esegue il controllo sulle procedure di backup.

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

            # 1. Verifica la presenza di software di backup
            backup_software = self._check_backup_software(target)

            # 2. Verifica la configurazione per backup dati
            data_backup_config = self._check_data_backup_config(target)

            # 3. Verifica la configurazione per backup sistema
            system_backup_config = self._check_system_backup_config(target)

            # 4. Verifica i backup recenti
            recent_backups = self._check_recent_backups(target)

            # Compila i risultati
            result['raw_data'] = {
                'backup_software': backup_software,
                'data_backup_config': data_backup_config,
                'system_backup_config': system_backup_config,
                'recent_backups': recent_backups
            }

            # Determina lo stato
            if data_backup_config['implemented'] and system_backup_config['implemented'] and recent_backups[
                'has_recent_backups']:
                result['status'] = "Sì completo"
            elif data_backup_config['implemented'] and recent_backups['has_recent_backups']:
                result['status'] = "Sì solo dati"
            elif system_backup_config['implemented'] and recent_backups['has_recent_backups']:
                result['status'] = "Sì solo sistema"
            else:
                result['status'] = "No"

            # Calcola punteggio
            result['score'] = self._calculate_custom_score(result['status'])

            # Aggiungi dettagli
            result['details'] = {
                'has_backup_software': bool(backup_software['software_found']),
                'has_data_backup_config': data_backup_config['implemented'],
                'has_system_backup_config': system_backup_config['implemented'],
                'has_recent_backups': recent_backups['has_recent_backups'],
                'backup_software_details': backup_software,
                'data_backup_details': data_backup_config,
                'system_backup_details': system_backup_config,
                'recent_backups_details': recent_backups
            }

            # Aggiungi note
            if result['status'] == "No":
                result[
                    'notes'] = "Non sono state trovate procedure di backup complete e regolari. È necessario implementare un sistema di backup per dati e sistema."
            elif result['status'] == "Sì solo dati":
                result[
                    'notes'] = "Sono implementati backup regolari per i dati, ma manca una soluzione per il backup del sistema."
            elif result['status'] == "Sì solo sistema":
                result[
                    'notes'] = "Sono implementati backup regolari per il sistema, ma manca una soluzione per il backup dei dati."
            else:
                result[
                    'notes'] = "È implementata una soluzione completa di backup per dati e sistema, con backup recenti disponibili."

        except Exception as e:
            self.log_error(target, e)
            result['status'] = "ERROR"
            result['details'] = {'error': str(e)}
            result['score'] = 0
        finally:
            duration = time.time() - start_time
            self.log_check_end(target, result['status'], duration)

        return result

    def _check_backup_software(self, target: Target) -> Dict:
        """
        Verifica la presenza di software di backup.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sul software di backup
        """
        software = {
            'software_found': False,
            'software_names': [],
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Lista di software di backup comuni su Linux/Unix
            backup_tools = [
                'rsync', 'tar', 'duplicity', 'borgbackup', 'bacula', 'bareos',
                'amanda', 'rclone', 'restic', 'duplicati', 'rdiff-backup', 'kbackup'
            ]

            for tool in backup_tools:
                # Verifica la presenza del comando
                cmd = f"which {tool} 2>/dev/null || command -v {tool} 2>/dev/null"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    software['software_found'] = True
                    software['software_names'].append(tool)
                    software['details'].append(f"Software di backup trovato: {tool}")

            # Verifica anche service attivi di backup
            service_names = ['bacula-fd', 'bacula-sd', 'bacula-dir', 'bareos-fd', 'bareos-sd', 'bareos-dir', 'amanda']
            for service in service_names:
                status = self.check_service_status(target, service)
                if status.get('running', False):
                    software['software_found'] = True
                    if service not in software['software_names']:
                        software['software_names'].append(service)
                    software['details'].append(f"Servizio di backup attivo: {service}")

        elif target.os_type.lower() == 'windows':
            # Lista di software di backup comuni su Windows
            windows_backup_tools = [
                'Windows Backup', 'Veeam', 'Acronis', 'Veritas', 'BackupExec', 'Commvault',
                'ArcServe', 'NTBackup', 'DPM', 'ShadowProtect', 'Macrium'
            ]

            # Verifica Windows Backup nativo
            cmd = 'powershell -Command "Get-WmiObject -Class Win32_Service -Filter \'Name=\"BITS\"\' | Where-Object {$_.State -eq \'Running\'} | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                cmd = 'powershell -Command "Get-WBPolicy -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    software['software_found'] = True
                    software['software_names'].append('Windows Backup')
                    software['details'].append("Windows Backup è configurato")

            # Verifica software di terze parti
            for tool in windows_backup_tools:
                if tool == 'Windows Backup':
                    continue  # Già controllato sopra

                cmd = f'powershell -Command "Get-ItemProperty HKLM:\\Software\\*\\*, HKLM:\\Software\\Wow6432Node\\*\\* | Where-Object {{ $_.DisplayName -match \'{tool}\' }} | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    software['software_found'] = True
                    software['software_names'].append(tool)
                    software['details'].append(f"Software di backup trovato: {tool}")

            # Verifica service attivi di backup
            backup_services = ['BITS', 'wbengine', 'VSS', 'BackupExecRPCService', 'VeeamBackupSvc']
            for service in backup_services:
                status = self.check_service_status(target, service)
                if status.get('running', False):
                    if not software['software_found']:  # Se non abbiamo ancora trovato software
                        software['software_found'] = True
                        software['details'].append(f"Servizio di backup attivo: {service}")

                    if service == 'BITS' and 'Windows Backup' not in software['software_names']:
                        software['software_names'].append('Windows Backup')
                    elif service == 'VeeamBackupSvc' and 'Veeam' not in software['software_names']:
                        software['software_names'].append('Veeam')
                    elif service == 'BackupExecRPCService' and 'BackupExec' not in software['software_names']:
                        software['software_names'].append('BackupExec')

        return software

    def _check_data_backup_config(self, target: Target) -> Dict:
        """
        Verifica la configurazione di backup per i dati.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulla configurazione di backup dati
        """
        config = {
            'implemented': False,
            'incremental': False,
            'scheduled': False,
            'off_site': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica cron job per backup
            cron_paths = ['/etc/crontab', '/var/spool/cron/crontabs/root', '/etc/cron.d']
            for path in cron_paths:
                if self.check_file_exists(target, path):
                    content = self.read_file_content(target, path)
                    if content and re.search(r'backup|rsync|tar|dump|archive', content, re.IGNORECASE):
                        config['scheduled'] = True
                        config['details'].append(f"Trovato job cron per backup in {path}")
                        config['implemented'] = True

            # Verifica script di backup
            backup_script_paths = [
                '/usr/local/bin/backup.sh',
                '/usr/local/bin/backup-data.sh',
                '/usr/local/sbin/backup.sh',
                '/opt/backup/backup.sh',
                '/etc/backup.conf'
            ]

            for path in backup_script_paths:
                if self.check_file_exists(target, path):
                    content = self.read_file_content(target, path)
                    if content:
                        config['details'].append(f"Trovato script di backup in {path}")

                        # Verifica backup incrementale
                        if re.search(r'--incremental|differential|--level', content, re.IGNORECASE):
                            config['incremental'] = True
                            config['details'].append("Configurazione per backup incrementale trovata")

                        # Verifica backup su posizione remota
                        if re.search(r'rsync.*:|\bscp\b|\bsftp\b|@|backup.*remote', content, re.IGNORECASE):
                            config['off_site'] = True
                            config['details'].append("Configurazione per backup remoto trovata")

                        config['implemented'] = True

            # Verifica configurazioni di tool specifici
            specific_config_paths = [
                '/etc/bacula/bacula-dir.conf',
                '/etc/bareos/bareos-dir.d',
                '/etc/duplicity',
                '/etc/restic',
                '/etc/duply',
                '/etc/rsnapshot.conf'
            ]

            for path in specific_config_paths:
                if self.check_file_exists(target, path):
                    config['details'].append(f"Trovata configurazione di backup in {path}")
                    config['implemented'] = True

                    # Per tool sofisticati, assumiamo che supportino backup incrementali
                    if path.endswith(('bacula-dir.conf', 'bareos-dir.d', 'rsnapshot.conf')):
                        config['incremental'] = True
                        config['scheduled'] = True

        elif target.os_type.lower() == 'windows':
            # Verifica Windows Backup
            cmd = 'powershell -Command "Get-WBPolicy -ErrorAction SilentlyContinue | Select-Object -ExpandProperty BackupTargets | ForEach-Object { $_.TargetPath } | Select-Object -First 1"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                config['implemented'] = True
                config['details'].append(f"Windows Backup configurato con destinazione: {result['stdout'].strip()}")

                # Verifica se ci sono backup pianificati
                cmd = 'powershell -Command "Get-WBSchedule -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    config['scheduled'] = True
                    config['details'].append("Windows Backup pianificato trovato")

                # Verifica backup incrementale
                cmd = 'powershell -Command "Get-WBPolicy -ErrorAction SilentlyContinue | Select-Object -ExpandProperty VolumesToBackup | Select-Object -ExpandProperty VssBackupOptions | Where-Object { $_ -eq \'VssIncrementalBackup\' } | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    config['incremental'] = True
                    config['details'].append("Windows Backup configurato per backup incrementali")

                # Controlla se il backup è su un'unità di rete o rimovibile (considerata off-site)
                cmd = 'powershell -Command "Get-WBBackupTarget -ErrorAction SilentlyContinue | Where-Object { $_.TargetPath -like \'\\\\*\' -or $_.TargetPath -like \'*:\' -and $_.TargetPath -notlike \'C:\' } | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    config['off_site'] = True
                    config['details'].append("Windows Backup configurato per backup su unità remota o rimovibile")

            # Verifica task pianificati per backup
            cmd = 'powershell -Command "Get-ScheduledTask -TaskName *backup* -ErrorAction SilentlyContinue | Where-Object { $_.State -eq \'Ready\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                config['scheduled'] = True
                config['details'].append("Task pianificati per backup trovati")
                config['implemented'] = True

            # Verifica registry per altre applicazioni di backup
            cmd = 'powershell -Command "Get-Item -Path \'HKLM:\\SOFTWARE\\*\\*\' | Where-Object { $_.Name -match \'backup|veeam|acronis\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                config['details'].append("Trovate configurazioni di backup nel registro di sistema")
                config['implemented'] = True

        return config

    def _check_system_backup_config(self, target: Target) -> Dict:
        """
        Verifica la configurazione di backup per il sistema.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulla configurazione di backup sistema
        """
        config = {
            'implemented': False,
            'full_system': False,
            'bootable': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica strumenti per system imaging
            system_tools = ['dd', 'partimage', 'clonezilla', 'ghost4linux', 'fsarchiver', 'mondorescue']
            for tool in system_tools:
                cmd = f"which {tool} 2>/dev/null || command -v {tool} 2>/dev/null"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    config['details'].append(f"Tool per backup di sistema trovato: {tool}")
                    config['implemented'] = True

                    if tool in ['dd', 'partimage', 'clonezilla', 'ghost4linux']:
                        config['full_system'] = True
                        config['bootable'] = True

            # Verifica script personalizzati
            script_paths = [
                '/usr/local/bin/system-backup.sh',
                '/usr/local/sbin/image-backup.sh',
                '/opt/backup/system-image.sh'
            ]

            for path in script_paths:
                if self.check_file_exists(target, path):
                    content = self.read_file_content(target, path)
                    if content and re.search(r'dd if=|dump|sfdisk|partimage|clonezilla', content, re.IGNORECASE):
                        config['details'].append(f"Script per backup di sistema trovato: {path}")
                        config['implemented'] = True
                        config['full_system'] = True

            # Verifica LVM snapshot
            cmd = "lvs 2>/dev/null | grep -i snapshot | wc -l"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                config['details'].append(f"Trovati {result['stdout'].strip()} LVM snapshot")
                config['implemented'] = True

        elif target.os_type.lower() == 'windows':
            # Verifica Windows System Restore
            cmd = 'powershell -Command "Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                config['details'].append(f"System Restore attivo con {result['stdout'].strip()} punti di ripristino")
                config['implemented'] = True

            # Verifica Windows Backup System State
            cmd = 'powershell -Command "Get-WBPolicy -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SystemState | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                config['details'].append("Windows Backup configurato per System State")
                config['implemented'] = True

            # Verifica Bare Metal Recovery
            cmd = 'powershell -Command "Get-WBBareMetalRecovery -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                config['details'].append("Windows Backup configurato per Bare Metal Recovery")
                config['implemented'] = True
                config['full_system'] = True
                config['bootable'] = True

            # Verifica software di imaging di sistema
            imaging_software = ['Acronis', 'Norton Ghost', 'Macrium Reflect', 'Paragon', 'Clonezilla', 'EaseUS',
                                'AOMEI']
            for software in imaging_software:
                cmd = f'powershell -Command "Get-ItemProperty HKLM:\\Software\\*\\*, HKLM:\\Software\\Wow6432Node\\*\\* | Where-Object {{ $_.DisplayName -match \'{software}\' }} | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    config['details'].append(f"Software di imaging sistema trovato: {software}")
                    config['implemented'] = True
                    config['full_system'] = True
                    config['bootable'] = True

        return config

    def _check_recent_backups(self, target: Target) -> Dict:
        """
        Verifica la presenza di backup recenti.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sui backup recenti
        """
        backups = {
            'has_recent_backups': False,
            'last_backup_date': None,
            'backup_locations': [],
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Direzioni comuni di backup
            backup_locations = [
                '/var/backups',
                '/backup',
                '/mnt/backup',
                '/opt/backup',
                '/data/backup'
            ]

            for location in backup_locations:
                if self.check_file_exists(target, location):
                    backups['backup_locations'].append(location)

                    # Trova l'ultima modifica nella directory di backup
                    cmd = f"find {location} -type f -exec stat -c '%Y' {{}} \\; | sort -nr | head -n1"
                    result = self.execute_command(target, cmd)

                    if result['exit_code'] == 0 and result['stdout'].strip():
                        try:
                            timestamp = int(result['stdout'].strip())
                            last_modified = datetime.datetime.fromtimestamp(timestamp)

                            # Se il backup è degli ultimi 7 giorni, lo consideriamo recente
                            days_old = (datetime.datetime.now() - last_modified).days

                            if days_old <= 7:
                                backups['has_recent_backups'] = True
                                backups['last_backup_date'] = last_modified.isoformat()
                                backups['details'].append(
                                    f"Backup recente trovato in {location} ({days_old} giorni fa)")
                        except ValueError:
                            pass

            # Verifica log di backup
            log_locations = [
                '/var/log/backup.log',
                '/var/log/bacula/bacula.log',
                '/var/log/rsync.log',
                '/var/log/backup/'
            ]

            for log in log_locations:
                if self.check_file_exists(target, log):
                    # Verifica l'ultima riga del log
                    cmd = f"tail -n 10 {log} | grep -i 'success\\|complete\\|finished'"
                    result = self.execute_command(target, cmd)

                    if result['exit_code'] == 0 and result['stdout'].strip():
                        backups['details'].append(f"Log di backup recente trovato in {log}")
                        backups['has_recent_backups'] = True

        elif target.os_type.lower() == 'windows':
            # Verifica Windows Backup History
            cmd = 'powershell -Command "Get-WBSummary -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LastSuccessfulBackupTime | ForEach-Object { $_.ToString(\'yyyy-MM-dd\') }"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                try:
                    last_backup = result['stdout'].strip()
                    last_backup_date = datetime.datetime.strptime(last_backup, '%Y-%m-%d')
                    days_old = (datetime.datetime.now() - last_backup_date).days

                    if days_old <= 7:
                        backups['has_recent_backups'] = True
                        backups['last_backup_date'] = last_backup
                        backups['details'].append(f"Windows Backup recente trovato ({days_old} giorni fa)")
                except (ValueError, TypeError):
                    pass

            # Verifica System Restore Points recenti
            cmd = 'powershell -Command "Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty CreationTime | ForEach-Object { $_.ToString(\'yyyy-MM-dd\') }"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                try:
                    last_restore = result['stdout'].strip()
                    last_restore_date = datetime.datetime.strptime(last_restore, '%Y-%m-%d')
                    days_old = (datetime.datetime.now() - last_restore_date).days

                    if days_old <= 7:
                        backups['has_recent_backups'] = True
                        if not backups['last_backup_date'] or last_restore > backups['last_backup_date']:
                            backups['last_backup_date'] = last_restore
                        backups['details'].append(f"System Restore Point recente trovato ({days_old} giorni fa)")
                except (ValueError, TypeError):
                    pass

            # Cerca directory di backup comuni
            backup_locations = [
                'D:\\Backup',
                'E:\\Backup',
                'C:\\Backup',
                'C:\\Windows\\Backup'
            ]

            for location in backup_locations:
                cmd = f'powershell -Command "Test-Path -Path \'{location}\'"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip().lower() == 'true':
                    backups['backup_locations'].append(location)

                    # Verifica l'ultima modifica nella directory
                    cmd = f'powershell -Command "Get-ChildItem -Path \'{location}\' -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty LastWriteTime | ForEach-Object {{ $_.ToString(\'yyyy-MM-dd\') }}"'
                    result = self.execute_command(target, cmd)

                    if result['exit_code'] == 0 and result['stdout'].strip():
                        try:
                            last_modified = result['stdout'].strip()
                            last_mod_date = datetime.datetime.strptime(last_modified, '%Y-%m-%d')
                            days_old = (datetime.datetime.now() - last_mod_date).days

                            if days_old <= 7:
                                backups['has_recent_backups'] = True
                                if not backups['last_backup_date'] or last_modified > backups['last_backup_date']:
                                    backups['last_backup_date'] = last_modified
                                backups['details'].append(
                                    f"File di backup recente trovato in {location} ({days_old} giorni fa)")
                        except (ValueError, TypeError):
                            pass

        return backups

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
        elif status == "Sì solo dati":
            return 70
        elif status == "Sì solo sistema":
            return 60
        elif status == "No":
            return 0
        else:
            return 0


class BackupTestingCheck(BaseCheck):
    """
    Controllo per verificare il test dei backup (ABSC 13.2.1-13.2.2).

    Verifica se vengono effettuati regolarmente test di ripristino dai backup.
    """

    ID = "13.2.1-13.2.2"
    NAME = "Test di ripristino"
    DESCRIPTION = "Verifica dell'esecuzione regolare di test di ripristino dai backup"
    QUESTION = "Vengono effettuati regolarmente test di ripristino dai backup?"
    POSSIBLE_ANSWERS = ["Sì completo", "Sì parziale", "No"]
    CATEGORY = "Backup"
    PRIORITY = 2  # Media priorità

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Esegue il controllo sui test di ripristino.

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

            # 1. Verifica procedure documentate di test
            documented_procedures = self._check_documented_procedures(target)

            # 2. Verifica log di test recenti
            recent_test_logs = self._check_recent_test_logs(target)

            # 3. Verifica ambienti di test per il ripristino
            test_environments = self._check_test_environments(target)

            # Compila i risultati
            result['raw_data'] = {
                'documented_procedures': documented_procedures,
                'recent_test_logs': recent_test_logs,
                'test_environments': test_environments
            }

            # Determina lo stato
            if documented_procedures['implemented'] and recent_test_logs['implemented'] and test_environments[
                'implemented']:
                result['status'] = "Sì completo"
            elif (documented_procedures['implemented'] and recent_test_logs['implemented']) or \
                    (documented_procedures['implemented'] and test_environments['implemented']) or \
                    (recent_test_logs['implemented'] and test_environments['implemented']):
                result['status'] = "Sì parziale"
            else:
                result['status'] = "No"

            # Calcola punteggio
            result['score'] = self._calculate_custom_score(result['status'])

            # Aggiungi dettagli
            result['details'] = {
                'has_documented_procedures': documented_procedures['implemented'],
                'has_recent_test_logs': recent_test_logs['implemented'],
                'has_test_environments': test_environments['implemented'],
                'documented_procedures_details': documented_procedures,
                'recent_test_logs_details': recent_test_logs,
                'test_environments_details': test_environments
            }

            # Aggiungi note
            if result['status'] == "No":
                result[
                    'notes'] = "Non sono stati trovati test di ripristino dai backup. È necessario implementare procedure regolari di test per verificare l'efficacia dei backup."
            elif result['status'] == "Sì parziale":
                result[
                    'notes'] = "Sono implementati alcuni elementi dei test di ripristino, ma la procedura non è completa. È consigliabile migliorare le procedure di test."
            else:
                result[
                    'notes'] = "È implementata una procedura completa di test dei backup, con procedure documentate, log di test recenti e ambienti di test dedicati."

        except Exception as e:
            self.log_error(target, e)
            result['status'] = "ERROR"
            result['details'] = {'error': str(e)}
            result['score'] = 0
        finally:
            duration = time.time() - start_time
            self.log_check_end(target, result['status'], duration)

        return result

    def _check_documented_procedures(self, target: Target) -> Dict:
        """
        Verifica la presenza di procedure documentate per il test dei backup.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulle procedure documentate
        """
        procedures = {
            'implemented': False,
            'documents_found': [],
            'details': []
        }

        # Cerca documenti di procedura comuni
        procedure_docs = [
            # Linux/Unix
            '/etc/backup/test-procedure.txt',
            '/etc/backup/test-procedure.md',
            '/etc/backup/test-procedure.pdf',
            '/usr/local/doc/backup-test.txt',
            '/opt/backup/docs/test-procedure.txt',
            # Windows
            'C:\\Backup\\Docs\\TestProcedure.txt',
            'C:\\Backup\\Docs\\TestProcedure.docx',
            'C:\\Backup\\Docs\\TestProcedure.pdf',
            'C:\\ProgramData\\Backup\\Docs\\TestProcedure.txt'
        ]

        for doc in procedure_docs:
            if self.check_file_exists(target, doc):
                procedures['documents_found'].append(doc)
                procedures['details'].append(f"Documento di procedura trovato: {doc}")
                procedures['implemented'] = True

        # Cerca directory di documentazione
        doc_dirs = [
            # Linux/Unix
            '/etc/backup/docs',
            '/opt/backup/docs',
            '/usr/share/doc/backup',
            # Windows
            'C:\\Backup\\Docs',
            'C:\\ProgramData\\Backup\\Docs'
        ]

        for dir_path in doc_dirs:
            if self.check_file_exists(target, dir_path):
                # Cerca file contenenti "test" o "restore" nella directory
                if target.os_type.lower() in ['linux', 'unix']:
                    cmd = f"find {dir_path} -type f -name '*test*' -o -name '*restore*' | head -5"
                else:  # Windows
                    cmd = f'powershell -Command "Get-ChildItem -Path \'{dir_path}\' -Recurse -File | Where-Object {{ $_.Name -match \'test|restore\' }} | Select-Object -First 5 -ExpandProperty FullName"'

                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    for line in result['stdout'].strip().split('\n'):
                        doc_path = line.strip()
                        if doc_path and doc_path not in procedures['documents_found']:
                            procedures['documents_found'].append(doc_path)
                            procedures['details'].append(f"Documento di procedura trovato: {doc_path}")
                            procedures['implemented'] = True

        # Se abbiamo trovato documenti ma non siamo sicuri del contenuto, verifichiamo
        if procedures['documents_found'] and not procedures['implemented']:
            for doc_path in procedures['documents_found']:
                content = self.read_file_content(target, doc_path)
                if content and re.search(r'test|restore|verify|validation|procedure', content, re.IGNORECASE):
                    procedures['implemented'] = True
                    procedures['details'].append(f"Il documento {doc_path} contiene procedure di test")

        return procedures

    def _check_recent_test_logs(self, target: Target) -> Dict:
        """
        Verifica la presenza di log di test recenti.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sui log di test
        """
        logs = {
            'implemented': False,
            'last_test_date': None,
            'logs_found': [],
            'details': []
        }

        # Cerca file di log di test comuni
        test_logs = [
            # Linux/Unix
            '/var/log/backup-test.log',
            '/var/log/backup/test.log',
            '/var/log/backup/restore-test.log',
            '/opt/backup/logs/test.log',
            # Windows
            'C:\\Backup\\Logs\\Test.log',
            'C:\\Backup\\Logs\\RestoreTest.log',
            'C:\\ProgramData\\Backup\\Logs\\Test.log'
        ]

        for log_path in test_logs:
            if self.check_file_exists(target, log_path):
                logs['logs_found'].append(log_path)

                # Verifica la data dell'ultima modifica
                if target.os_type.lower() in ['linux', 'unix']:
                    cmd = f"stat -c %Y {log_path}"
                    result = self.execute_command(target, cmd)

                    if result['exit_code'] == 0 and result['stdout'].strip():
                        try:
                            timestamp = int(result['stdout'].strip())
                            last_modified = datetime.datetime.fromtimestamp(timestamp)

                            # Se il log è stato modificato negli ultimi 90 giorni, lo consideriamo recente
                            days_old = (datetime.datetime.now() - last_modified).days

                            if days_old <= 90:
                                logs['implemented'] = True
                                logs['last_test_date'] = last_modified.isoformat()
                                logs['details'].append(
                                    f"Log di test recente trovato: {log_path} ({days_old} giorni fa)")
                        except ValueError:
                            pass
                else:  # Windows
                    cmd = f'powershell -Command "(Get-Item -Path \'{log_path}\').LastWriteTime.ToString(\'yyyy-MM-dd\')"'
                    result = self.execute_command(target, cmd)

                    if result['exit_code'] == 0 and result['stdout'].strip():
                        try:
                            last_modified = result['stdout'].strip()
                            last_mod_date = datetime.datetime.strptime(last_modified, '%Y-%m-%d')
                            days_old = (datetime.datetime.now() - last_mod_date).days

                            if days_old <= 90:
                                logs['implemented'] = True
                                logs['last_test_date'] = last_modified
                                logs['details'].append(
                                    f"Log di test recente trovato: {log_path} ({days_old} giorni fa)")
                        except (ValueError, TypeError):
                            pass

        # Cerca anche nei log generali menzioni di test di backup
        general_logs = [
            # Linux/Unix
            '/var/log/messages',
            '/var/log/syslog',
            '/var/log/backup.log',
            # Windows
            'C:\\Windows\\Logs\\WindowsBackup\\BackupReport.log'
        ]

        for log_path in general_logs:
            if self.check_file_exists(target, log_path):
                # Cerca menzioni di test di backup nei log
                if target.os_type.lower() in ['linux', 'unix']:
                    cmd = f"grep -i 'backup test\\|restore test\\|test restore\\|verification' {log_path} | tail -5"
                else:  # Windows
                    cmd = f'powershell -Command "Get-Content -Path \'{log_path}\' | Select-String -Pattern \'backup test|restore test|test restore|verification\' | Select-Object -Last 5"'

                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    logs['logs_found'].append(log_path)
                    logs['details'].append(f"Menzioni di test di backup trovate in {log_path}")

                    # Se troviamo menzioni di test, consideriamo implementata la verifica
                    logs['implemented'] = True

        return logs

    def _check_test_environments(self, target: Target) -> Dict:
        """
        Verifica la presenza di ambienti dedicati per il test di ripristino.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sugli ambienti di test
        """
        environments = {
            'implemented': False,
            'virtual_test_env': False,
            'dedicated_hardware': False,
            'sandbox_environment': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica presenza di strumenti di virtualizzazione
            virtualization_tools = ['virtualbox', 'vmware', 'kvm', 'xen', 'qemu', 'virt-manager']
            for tool in virtualization_tools:
                cmd = f"which {tool} 2>/dev/null || command -v {tool} 2>/dev/null"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    environments['virtual_test_env'] = True
                    environments['details'].append(f"Strumento di virtualizzazione trovato: {tool}")
                    environments['implemented'] = True

            # Verifica presenza di script di test con riferimenti ad ambienti
            test_scripts = [
                '/usr/local/bin/test-restore.sh',
                '/usr/local/bin/verify-backup.sh',
                '/opt/backup/test-environment.sh',
                '/opt/testing/restore-test.sh'
            ]

            for script in test_scripts:
                if self.check_file_exists(target, script):
                    content = self.read_file_content(target, script)
                    if content:
                        if re.search(r'virtual|vm\b|vmware|virtualbox|sandbox|test environment', content,
                                     re.IGNORECASE):
                            environments['sandbox_environment'] = True
                            environments['details'].append(
                                f"Script con riferimenti ad ambiente di test trovato: {script}")
                            environments['implemented'] = True

                        if re.search(r'dedicated|hardware|physical|staging', content, re.IGNORECASE):
                            environments['dedicated_hardware'] = True
                            environments['details'].append(
                                f"Script con riferimenti a hardware dedicato trovato: {script}")
                            environments['implemented'] = True

            # Verifica presenza di directory di test
            test_dirs = ['/opt/test-env', '/opt/restore-test', '/var/test-restore']
            for dir_path in test_dirs:
                if self.check_file_exists(target, dir_path):
                    environments['details'].append(f"Directory per ambiente di test trovata: {dir_path}")
                    environments['sandbox_environment'] = True
                    environments['implemented'] = True

        elif target.os_type.lower() == 'windows':
            # Verifica presenza di strumenti di virtualizzazione
            virtualization_tools = ['VMware', 'VirtualBox', 'Hyper-V']
            for tool in virtualization_tools:
                cmd = f'powershell -Command "Get-ItemProperty HKLM:\\Software\\*\\*, HKLM:\\Software\\Wow6432Node\\*\\* | Where-Object {{ $_.DisplayName -match \'{tool}\' }} | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    environments['virtual_test_env'] = True
                    environments['details'].append(f"Strumento di virtualizzazione trovato: {tool}")
                    environments['implemented'] = True

            # Verifica se Hyper-V è abilitato
            cmd = 'powershell -Command "Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue | Select-Object -ExpandProperty State"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == 'Enabled':
                environments['virtual_test_env'] = True
                environments['details'].append("Hyper-V è abilitato")
                environments['implemented'] = True

            # Verifica presenza di script PowerShell per test
            script_paths = [
                'C:\\Backup\\Scripts\\TestRestore.ps1',
                'C:\\Backup\\Scripts\\VerifyBackup.ps1',
                'C:\\ProgramData\\Backup\\TestEnvironment.ps1'
            ]

            for script in script_paths:
                if self.check_file_exists(target, script):
                    content = self.read_file_content(target, script)
                    if content:
                        if re.search(r'virtual|vm\b|vmware|hyper-v|sandbox|test environment', content, re.IGNORECASE):
                            environments['sandbox_environment'] = True
                            environments['details'].append(
                                f"Script con riferimenti ad ambiente di test trovato: {script}")
                            environments['implemented'] = True

                        if re.search(r'dedicated|hardware|physical|staging', content, re.IGNORECASE):
                            environments['dedicated_hardware'] = True
                            environments['details'].append(
                                f"Script con riferimenti a hardware dedicato trovato: {script}")
                            environments['implemented'] = True

            # Verifica presenza di directory di test
            test_dirs = ['C:\\TestEnv', 'D:\\RestoreTest', 'C:\\Backup\\TestEnv']
            for dir_path in test_dirs:
                cmd = f'powershell -Command "Test-Path -Path \'{dir_path}\'"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip().lower() == 'true':
                    environments['details'].append(f"Directory per ambiente di test trovata: {dir_path}")
                    environments['sandbox_environment'] = True
                    environments['implemented'] = True

        return environments

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
            return 70
        elif status == "No":
            return 0
        else:
            return 0