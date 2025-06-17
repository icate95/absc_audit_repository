"""
Encryption Checks - Implementazione dei controlli di cifratura ABSC 3.x.

Questo modulo implementa i controlli relativi alla cifratura dei dati
secondo le specifiche ABSC 3.x.
"""

import time
import re
import os
from typing import Dict, List, Optional, Any, Tuple

from absc_audit.checks.base import BaseCheck
from absc_audit.storage.models import Target
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class StorageEncryptionCheck(BaseCheck):
    """
    Controllo per verificare la cifratura dei dati critici (ABSC 3.3.1-3.3.2).

    Verifica se sono utilizzati meccanismi di cifratura per i dati memorizzati.
    """

    ID = "3.3.1-3.3.2"
    NAME = "Cifratura dei dati critici"
    DESCRIPTION = "Verifica dell'utilizzo di meccanismi di cifratura per i dati memorizzati"
    QUESTION = "Vengono utilizzati meccanismi di cifratura per proteggere i dati memorizzati più critici?"
    POSSIBLE_ANSWERS = ["Sì completo", "Sì parziale", "No"]
    CATEGORY = "Encryption"
    PRIORITY = 3  # Bassa priorità

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Esegue il controllo sulla cifratura dei dati.

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

            # 1. Verifica la presenza di soluzioni di cifratura del disco
            disk_encryption = self._check_disk_encryption(target)

            # 2. Verifica soluzioni di cifratura a livello di file/directory
            file_encryption = self._check_file_encryption(target)

            # 3. Verifica cifratura del database
            database_encryption = self._check_database_encryption(target)

            # Compila i risultati
            result['raw_data'] = {
                'disk_encryption': disk_encryption,
                'file_encryption': file_encryption,
                'database_encryption': database_encryption
            }

            # Determina lo stato
            if disk_encryption['implemented'] and (
                    file_encryption['implemented'] or database_encryption['implemented']):
                result['status'] = "Sì completo"
            elif disk_encryption['implemented'] or file_encryption['implemented'] or database_encryption['implemented']:
                result['status'] = "Sì parziale"
            else:
                result['status'] = "No"

            # Calcola punteggio
            result['score'] = self._calculate_custom_score(result['status'])

            # Aggiungi dettagli
            result['details'] = {
                'has_disk_encryption': disk_encryption['implemented'],
                'has_file_encryption': file_encryption['implemented'],
                'has_database_encryption': database_encryption['implemented'],
                'disk_encryption_details': disk_encryption,
                'file_encryption_details': file_encryption,
                'database_encryption_details': database_encryption
            }

            # Aggiungi note
            if result['status'] == "No":
                result[
                    'notes'] = "Non sono stati trovati meccanismi di cifratura per i dati memorizzati. È necessario implementare soluzioni di cifratura per proteggere i dati critici."
            elif result['status'] == "Sì parziale":
                result[
                    'notes'] = "Sono implementati alcuni meccanismi di cifratura, ma la protezione non è completa. Si consiglia di estendere la cifratura a tutte le categorie di dati critici."
            else:
                result[
                    'notes'] = "Sono implementati meccanismi completi di cifratura per proteggere i dati memorizzati, inclusa cifratura del disco e altre misure di protezione specifiche."

        except Exception as e:
            self.log_error(target, e)
            result['status'] = "ERROR"
            result['details'] = {'error': str(e)}
            result['score'] = 0
        finally:
            duration = time.time() - start_time
            self.log_check_end(target, result['status'], duration)

        return result

    def _check_disk_encryption(self, target: Target) -> Dict:
        """
        Verifica la presenza di soluzioni di cifratura del disco.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulla cifratura del disco
        """
        disk_enc = {
            'implemented': False,
            'full_disk_encryption': False,
            'volume_encryption': False,
            'tool_name': None,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica LUKS
            cmd = "lsblk -o NAME,TYPE,MOUNTPOINT,UUID,FSTYPE | grep -i 'crypt\\|luks'"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                disk_enc['implemented'] = True
                disk_enc['full_disk_encryption'] = "crypt" in result['stdout'].lower()
                disk_enc['volume_encryption'] = True
                disk_enc['tool_name'] = "LUKS"
                disk_enc['details'].append("Trovate partizioni cifrate con LUKS")

            # Verifica dm-crypt
            cmd = "dmsetup ls --target crypt"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                disk_enc['implemented'] = True
                disk_enc['volume_encryption'] = True
                disk_enc['tool_name'] = "dm-crypt"
                disk_enc['details'].append("Trovati device mapper criptati")

            # Verifica eCryptfs
            cmd = "mount | grep -i ecryptfs"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                disk_enc['implemented'] = True
                disk_enc['volume_encryption'] = True
                disk_enc['tool_name'] = "eCryptfs"
                disk_enc['details'].append("Trovati filesystem eCryptfs montati")

            # Verifica EncFS
            cmd = "ps aux | grep -i encfs | grep -v grep"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                disk_enc['implemented'] = True
                disk_enc['volume_encryption'] = True
                disk_enc['tool_name'] = "EncFS"
                disk_enc['details'].append("Trovati filesystem EncFS in uso")

        elif target.os_type.lower() == 'windows':
            # Verifica BitLocker
            cmd = 'powershell -Command "Get-BitLockerVolume | Select-Object -Property MountPoint,ProtectionStatus | ForEach-Object { $_.MountPoint + \' - \' + $_.ProtectionStatus }"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                if "On" in result['stdout']:
                    disk_enc['implemented'] = True
                    disk_enc['volume_encryption'] = True
                    disk_enc['tool_name'] = "BitLocker"
                    disk_enc['details'].append("BitLocker attivo sui seguenti volumi:")

                    # Aggiungi dettagli sui volumi protetti
                    for line in result['stdout'].strip().split('\n'):
                        if "On" in line:
                            disk_enc['details'].append(f"  - {line.strip()}")

                    # Verifica se il sistema è completamente protetto
                    if "C: - On" in result['stdout'] or "C:\\ - On" in result['stdout']:
                        disk_enc['full_disk_encryption'] = True

            # Verifica EFS (Encrypting File System)
            cmd = 'powershell -Command "Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object { $_.DeviceID + \' - Support EFS: \' + $_.SupportsFileBasedCompression }"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                if "Support EFS: True" in result['stdout']:
                    # EFS è disponibile, verifica se viene utilizzato
                    cmd = 'powershell -Command "Get-ChildItem -Path C:\\ -Recurse -Force -ErrorAction SilentlyContinue | Get-ItemProperty -Name Attributes -ErrorAction SilentlyContinue | Where-Object { $_.Attributes -match \'Encrypted\' } | Measure-Object | Select-Object -ExpandProperty Count"'
                    result = self.execute_command(target, cmd)

                    if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                        disk_enc['implemented'] = True
                        disk_enc['volume_encryption'] = True
                        disk_enc['tool_name'] = "EFS"
                        disk_enc['details'].append(f"EFS in uso con {result['stdout'].strip()} file cifrati")

            # Verifica software di terze parti
            encryption_software = ['VeraCrypt', 'TrueCrypt', 'PGP Disk', 'DiskCryptor', 'Symantec Endpoint Encryption',
                                   'McAfee Drive Encryption']
            for software in encryption_software:
                cmd = f'powershell -Command "Get-ItemProperty HKLM:\\Software\\*\\*, HKLM:\\Software\\Wow6432Node\\*\\* | Where-Object {{ $_.DisplayName -match \'{software}\' }} | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    disk_enc['implemented'] = True
                    disk_enc['volume_encryption'] = True
                    disk_enc['tool_name'] = software
                    disk_enc['details'].append(f"Software di cifratura disco trovato: {software}")

                    # Per VeraCrypt, possiamo verificare se ci sono volumi montati
                    if software == 'VeraCrypt':
                        cmd = 'powershell -Command "Get-Process -Name VeraCrypt -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
                        result = self.execute_command(target, cmd)

                        if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                            disk_enc['details'].append("VeraCrypt è in esecuzione")

        return disk_enc

    def _check_file_encryption(self, target: Target) -> Dict:
        """
        Verifica la presenza di soluzioni di cifratura a livello di file/directory.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulla cifratura dei file
        """
        file_enc = {
            'implemented': False,
            'tool_name': None,
            'encrypted_files_found': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica GPG
            cmd = "which gpg 2>/dev/null || command -v gpg 2>/dev/null"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                file_enc['tool_name'] = "GPG"
                file_enc['details'].append("GPG installato")

                # Verifica se ci sono file .gpg
                cmd = "find /home -name '*.gpg' -o -name '*.pgp' 2>/dev/null | head -5"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    file_enc['implemented'] = True
                    file_enc['encrypted_files_found'] = True
                    file_enc['details'].append("Trovati file cifrati con GPG")

            # Verifica openssl
            cmd = "which openssl 2>/dev/null || command -v openssl 2>/dev/null"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                file_enc['details'].append("OpenSSL installato")

                # Verifica se ci sono file .enc
                cmd = "find /home -name '*.enc' 2>/dev/null | head -5"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    file_enc['implemented'] = True
                    file_enc['encrypted_files_found'] = True
                    file_enc['tool_name'] = "OpenSSL"
                    file_enc['details'].append("Trovati file potenzialmente cifrati con OpenSSL")

            # Verifica mcrypt
            cmd = "which mcrypt 2>/dev/null || command -v mcrypt 2>/dev/null"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                file_enc['details'].append("MCrypt installato")

                # Verifica se ci sono file .nc
                cmd = "find /home -name '*.nc' 2>/dev/null | head -5"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    file_enc['implemented'] = True
                    file_enc['encrypted_files_found'] = True
                    file_enc['tool_name'] = "MCrypt"
                    file_enc['details'].append("Trovati file potenzialmente cifrati con MCrypt")

            # Verifica 7z con crittografia
            cmd = "which 7z 2>/dev/null || command -v 7z 2>/dev/null"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                file_enc['details'].append("7z installato (supporta cifratura)")

        elif target.os_type.lower() == 'windows':
            # Verifica EFS (Encrypting File System) a livello di file
            cmd = 'powershell -Command "Get-ChildItem -Path C:\\Users -Recurse -Force -ErrorAction SilentlyContinue | Get-ItemProperty -Name Attributes -ErrorAction SilentlyContinue | Where-Object { $_.Attributes -match \'Encrypted\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                file_enc['implemented'] = True
                file_enc['encrypted_files_found'] = True
                file_enc['tool_name'] = "EFS"
                file_enc['details'].append(f"Trovati {result['stdout'].strip()} file cifrati con EFS")

            # Verifica 7-Zip
            cmd = 'powershell -Command "Get-ItemProperty HKLM:\\Software\\*\\*, HKLM:\\Software\\Wow6432Node\\*\\* | Where-Object { $_.DisplayName -match \'7-Zip\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                file_enc['details'].append("7-Zip installato (supporta cifratura)")

            # Verifica WinZip
            cmd = 'powershell -Command "Get-ItemProperty HKLM:\\Software\\*\\*, HKLM:\\Software\\Wow6432Node\\*\\* | Where-Object { $_.DisplayName -match \'WinZip\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                file_enc['details'].append("WinZip installato (supporta cifratura)")

            # Verifica AES Crypt o altri tool specifici di cifratura file
            encryption_software = ['AES Crypt', 'AxCrypt', 'Gpg4win', 'PGP Desktop']
            for software in encryption_software:
                cmd = f'powershell -Command "Get-ItemProperty HKLM:\\Software\\*\\*, HKLM:\\Software\\Wow6432Node\\*\\* | Where-Object {{ $_.DisplayName -match \'{software}\' }} | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    file_enc['implemented'] = True
                    file_enc['tool_name'] = software
                    file_enc['details'].append(f"Software di cifratura file trovato: {software}")

            # Cerca file con estensioni tipiche di cifratura
            encrypted_extensions = ['gpg', 'pgp', 'asc', 'aex', 'axc', 'enc', 'crypted']
            for ext in encrypted_extensions:
                cmd = f'powershell -Command "Get-ChildItem -Path C:\\Users -Include *.{ext} -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                    file_enc['implemented'] = True
                    file_enc['encrypted_files_found'] = True
                    file_enc['details'].append(f"Trovati {result['stdout'].strip()} file con estensione .{ext}")

        return file_enc

    def _check_database_encryption(self, target: Target) -> Dict:
        """
        Verifica la presenza di cifratura a livello di database.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulla cifratura dei database
        """
        db_enc = {
            'implemented': False,
            'encrypted_databases': [],
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica MySQL/MariaDB
            cmd = "ps aux | grep -E 'mysql|mariadb' | grep -v grep"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                # MySQL/MariaDB è in esecuzione, controlla configurazione
                mysql_config_paths = [
                    '/etc/mysql/my.cnf',
                    '/etc/mysql/mysql.conf.d/mysqld.cnf',
                    '/etc/my.cnf',
                    '/etc/my.cnf.d/server.cnf'
                ]

                for config_path in mysql_config_paths:
                    content = self.read_file_content(target, config_path)
                    if content:
                        # Cerca direttive di cifratura
                        if re.search(r'ssl|encrypt|sha2_password|aes_encrypt', content, re.IGNORECASE):
                            db_enc['implemented'] = True
                            db_enc['encrypted_databases'].append("MySQL/MariaDB")
                            db_enc['details'].append(
                                f"Trovata configurazione di cifratura MySQL/MariaDB in {config_path}")

            # Verifica PostgreSQL
            cmd = "ps aux | grep postgres | grep -v grep"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                # PostgreSQL è in esecuzione, controlla configurazione
                pg_config_paths = [
                    '/etc/postgresql/*/main/postgresql.conf',
                    '/var/lib/postgresql/*/main/postgresql.conf'
                ]

                for pattern in pg_config_paths:
                    cmd = f"find {pattern} -type f 2>/dev/null"
                    result = self.execute_command(target, cmd)

                    if result['exit_code'] == 0 and result['stdout'].strip():
                        for config_path in result['stdout'].strip().split('\n'):
                            content = self.read_file_content(target, config_path)
                            if content:
                                # Cerca direttive di cifratura
                                if re.search(r'ssl|encrypt|pgcrypto|ssl_ciphers', content, re.IGNORECASE):
                                    db_enc['implemented'] = True
                                    db_enc['encrypted_databases'].append("PostgreSQL")
                                    db_enc['details'].append(
                                        f"Trovata configurazione di cifratura PostgreSQL in {config_path}")

            # Verifica SQLite
            sqlite_paths = [
                '/var/www/',
                '/opt/',
                '/srv/'
            ]

            for base_path in sqlite_paths:
                cmd = f"find {base_path} -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null | head -5"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    # Controlla se i database sono cifrati
                    # Nota: difficile determinare se un database SQLite è cifrato senza accesso diretto
                    pass

        elif target.os_type.lower() == 'windows':
            # Verifica SQL Server
            cmd = 'powershell -Command "Get-Service -Name MSSQLSERVER,SQLSERVERAGENT -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq \'Running\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                # SQL Server è in esecuzione, controlla TDE o altre misure
                cmd = 'powershell -Command "Import-Module SQLPS -ErrorAction SilentlyContinue; if (Get-Command -Name Invoke-Sqlcmd -ErrorAction SilentlyContinue) { Invoke-Sqlcmd -Query \'SELECT name FROM sys.databases WHERE is_encrypted = 1;\' -ServerInstance localhost -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count } else { Write-Output \'SQLPS module not available\' }"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0:
                    if result['stdout'].strip() != '0' and result['stdout'].strip() != 'SQLPS module not available':
                        db_enc['implemented'] = True
                        db_enc['encrypted_databases'].append("SQL Server (TDE)")
                        db_enc['details'].append(
                            f"Trovati {result['stdout'].strip()} database SQL Server con TDE abilitato")

            # Verifica MySQL/MariaDB su Windows
            cmd = 'powershell -Command "Get-Service -Name MySQL* -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq \'Running\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                # MySQL/MariaDB è in esecuzione, controlla configurazione
                mysql_config_paths = [
                    'C:\\ProgramData\\MySQL\\MySQL Server *\\my.ini',
                    'C:\\Program Files\\MySQL\\MySQL Server *\\my.ini'
                ]

                for pattern in mysql_config_paths:
                    cmd = f'powershell -Command "Get-Item -Path \'{pattern}\' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName"'
                    result = self.execute_command(target, cmd)

                    if result['exit_code'] == 0 and result['stdout'].strip():
                        for config_path in result['stdout'].strip().split('\n'):
                            content = self.read_file_content(target, config_path)
                            if content:
                                # Cerca direttive di cifratura
                                if re.search(r'ssl|encrypt|sha2_password|aes_encrypt', content, re.IGNORECASE):
                                    db_enc['implemented'] = True
                                    db_enc['encrypted_databases'].append("MySQL/MariaDB")
                                    db_enc['details'].append(
                                        f"Trovata configurazione di cifratura MySQL/MariaDB in {config_path}")

            # Verifica PostgreSQL su Windows
            cmd = 'powershell -Command "Get-Service -Name postgresql* -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq \'Running\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                # PostgreSQL è in esecuzione, controlla configurazione
                pg_config_paths = [
                    'C:\\Program Files\\PostgreSQL\\*\\data\\postgresql.conf'
                ]

                for pattern in pg_config_paths:
                    cmd = f'powershell -Command "Get-Item -Path \'{pattern}\' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName"'
                    result = self.execute_command(target, cmd)

                    if result['exit_code'] == 0 and result['stdout'].strip():
                        for config_path in result['stdout'].strip().split('\n'):
                            content = self.read_file_content(target, config_path)
                            if content:
                                # Cerca direttive di cifratura
                                if re.search(r'ssl|encrypt|pgcrypto|ssl_ciphers', content, re.IGNORECASE):
                                    db_enc['implemented'] = True
                                    db_enc['encrypted_databases'].append("PostgreSQL")
                                    db_enc['details'].append(
                                        f"Trovata configurazione di cifratura PostgreSQL in {config_path}")

        return db_enc

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


class TransportEncryptionCheck(BaseCheck):
    """
    Controllo per verificare la cifratura dei dati in transito (ABSC 3.1.1-3.2.1).

    Verifica se sono utilizzati meccanismi di cifratura per i dati in transito.
    """

    ID = "3.1.1-3.2.1"
    NAME = "Cifratura dei dati in transito"
    DESCRIPTION = "Verifica dell'utilizzo di meccanismi di cifratura per i dati in transito"
    QUESTION = "Vengono utilizzati canali cifrati per la trasmissione di dati e l'accesso alle risorse?"
    POSSIBLE_ANSWERS = ["Sì completo", "Sì parziale", "No"]
    CATEGORY = "Encryption"
    PRIORITY = 3  # Bassa priorità

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Esegue il controllo sulla cifratura dei dati in transito.

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

            # 1. Verifica servizi web (HTTPS)
            web_encryption = self._check_web_encryption(target)

            # 2. Verifica accesso remoto (SSH, RDP)
            remote_access_encryption = self._check_remote_access_encryption(target)

            # 3. Verifica email (SMTPS, IMAPS, etc.)
            email_encryption = self._check_email_encryption(target)

            # 4. Verifica VPN
            vpn_encryption = self._check_vpn_encryption(target)

            # Compila i risultati
            result['raw_data'] = {
                'web_encryption': web_encryption,
                'remote_access_encryption': remote_access_encryption,
                'email_encryption': email_encryption,
                'vpn_encryption': vpn_encryption
            }

            # Conta quanti tipi di cifratura sono implementati
            encryption_count = sum(
                1 for enc in [web_encryption, remote_access_encryption, email_encryption, vpn_encryption] if
                enc['implemented'])

            # Determina lo stato
            if encryption_count >= 3:  # Se almeno 3 tipi di cifratura sono implementati
                result['status'] = "Sì completo"
            elif encryption_count > 0:  # Se almeno un tipo di cifratura è implementato
                result['status'] = "Sì parziale"
            else:
                result['status'] = "No"

            # Calcola punteggio
            result['score'] = self._calculate_custom_score(result['status'])

            # Aggiungi dettagli
            result['details'] = {
                'has_web_encryption': web_encryption['implemented'],
                'has_remote_access_encryption': remote_access_encryption['implemented'],
                'has_email_encryption': email_encryption['implemented'],
                'has_vpn_encryption': vpn_encryption['implemented'],
                'web_encryption_details': web_encryption,
                'remote_access_encryption_details': remote_access_encryption,
                'email_encryption_details': email_encryption,
                'vpn_encryption_details': vpn_encryption
            }

            # Aggiungi note
            if result['status'] == "No":
                result[
                    'notes'] = "Non sono stati trovati meccanismi di cifratura per i dati in transito. È necessario implementare comunicazioni cifrate per proteggere le trasmissioni di dati."
            elif result['status'] == "Sì parziale":
                result[
                    'notes'] = "Sono implementati alcuni meccanismi di cifratura per i dati in transito, ma la protezione non è completa. Si consiglia di estendere la cifratura a tutti i canali di comunicazione."
            else:
                result[
                    'notes'] = "Sono implementati meccanismi completi di cifratura per i dati in transito, assicurando la protezione delle comunicazioni."

        except Exception as e:
            self.log_error(target, e)
            result['status'] = "ERROR"
            result['details'] = {'error': str(e)}
            result['score'] = 0
        finally:
            duration = time.time() - start_time
            self.log_check_end(target, result['status'], duration)

        return result

    def _check_web_encryption(self, target: Target) -> Dict:
        """
        Verifica la presenza di cifratura per servizi web (HTTPS).

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulla cifratura web
        """
        web_enc = {
            'implemented': False,
            'https_enabled': False,
            'hsts_enabled': False,
            'valid_certificate': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Controlla se ci sono server web in esecuzione
            web_servers = ['apache2', 'httpd', 'nginx', 'lighttpd']
            for server in web_servers:
                cmd = f"ps aux | grep -v grep | grep {server}"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    web_enc['details'].append(f"Server web trovato: {server}")

                    # Controlla configurazione per HTTPS
                    if server in ['apache2', 'httpd']:
                        ssl_config_paths = [
                            '/etc/apache2/sites-enabled/*-ssl.conf',
                            '/etc/apache2/sites-enabled/*.conf',
                            '/etc/httpd/conf.d/ssl.conf',
                            '/etc/httpd/conf/httpd.conf'
                        ]

                        for pattern in ssl_config_paths:
                            cmd = f"find {pattern} -type f -exec grep -l 'SSLEngine on' {{}} \\; 2>/dev/null"
                            result = self.execute_command(target, cmd)

                            if result['exit_code'] == 0 and result['stdout'].strip():
                                web_enc['https_enabled'] = True
                                web_enc['implemented'] = True
                                web_enc['details'].append(f"HTTPS abilitato in Apache: {result['stdout'].strip()}")

                                # Controlla HSTS
                                cmd = f"find {pattern} -type f -exec grep -l 'Strict-Transport-Security' {{}} \\; 2>/dev/null"
                                result = self.execute_command(target, cmd)

                                if result['exit_code'] == 0 and result['stdout'].strip():
                                    web_enc['hsts_enabled'] = True
                                    web_enc['details'].append("HSTS abilitato in Apache")

                    elif server == 'nginx':
                        nginx_config_paths = [
                            '/etc/nginx/sites-enabled/*.conf',
                            '/etc/nginx/conf.d/*.conf',
                            '/etc/nginx/nginx.conf'
                        ]

                        for pattern in nginx_config_paths:
                            cmd = f"find {pattern} -type f -exec grep -l 'listen.*ssl' {{}} \\; 2>/dev/null"
                            result = self.execute_command(target, cmd)

                            if result['exit_code'] == 0 and result['stdout'].strip():
                                web_enc['https_enabled'] = True
                                web_enc['implemented'] = True
                                web_enc['details'].append(f"HTTPS abilitato in Nginx: {result['stdout'].strip()}")

                                # Controlla HSTS
                                cmd = f"find {pattern} -type f -exec grep -l 'Strict-Transport-Security' {{}} \\; 2>/dev/null"
                                result = self.execute_command(target, cmd)

                                if result['exit_code'] == 0 and result['stdout'].strip():
                                    web_enc['hsts_enabled'] = True
                                    web_enc['details'].append("HSTS abilitato in Nginx")

            # Controlla certificati SSL
            ssl_cert_paths = [
                '/etc/ssl/certs',
                '/etc/pki/tls/certs',
                '/etc/apache2/ssl',
                '/etc/nginx/ssl'
            ]

            for path in ssl_cert_paths:
                if self.check_file_exists(target, path):
                    cmd = f"find {path} -name '*.crt' -o -name '*.pem' | head -5"
                    result = self.execute_command(target, cmd)

                    if result['exit_code'] == 0 and result['stdout'].strip():
                        web_enc['details'].append(f"Certificati SSL trovati in {path}")

                        # Verifica validità certificato (scadenza)
                        first_cert = result['stdout'].strip().split('\n')[0]
                        cmd = f"openssl x509 -noout -in {first_cert} -dates | grep notAfter"
                        result = self.execute_command(target, cmd)

                        if result['exit_code'] == 0 and result['stdout'].strip():
                            # Estrai la data di scadenza e verifica che sia nel futuro
                            # (Questo è semplificato, in un'implementazione reale si farebbe un confronto più preciso)
                            if 'notAfter=' in result['stdout'] and '2023' in result['stdout']:
                                web_enc['valid_certificate'] = True
                                web_enc['details'].append("Certificato SSL valido trovato")

        elif target.os_type.lower() == 'windows':
            # Controlla IIS
            cmd = 'powershell -Command "Get-Service -Name W3SVC -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq \'Running\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                web_enc['details'].append("IIS in esecuzione")

                # Controlla binding HTTPS
                cmd = 'powershell -Command "Import-Module WebAdministration -ErrorAction SilentlyContinue; if (Get-Command Get-WebBinding -ErrorAction SilentlyContinue) { Get-WebBinding | Where-Object { $_.protocol -eq \'https\' } | Measure-Object | Select-Object -ExpandProperty Count } else { Write-Output \'WebAdministration module not available\' }"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0:
                    if result['stdout'].strip() != '0' and result[
                        'stdout'].strip() != 'WebAdministration module not available':
                        web_enc['https_enabled'] = True
                        web_enc['implemented'] = True
                        web_enc['details'].append("HTTPS abilitato in IIS")

            # Controlla certificati nel certificate store
            cmd = 'powershell -Command "Get-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object { $_.NotAfter -gt (Get-Date) } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                web_enc['valid_certificate'] = True
                web_enc['details'].append(
                    f"Trovati {result['stdout'].strip()} certificati validi nel certificate store")

                # Se abbiamo certificati validi e IIS, assumiamo che HTTPS sia configurato
                if web_enc['details'][0] == "IIS in esecuzione":
                    web_enc['https_enabled'] = True
                    web_enc['implemented'] = True

            # Controlla altri server web su Windows
            web_servers = ['Apache', 'Nginx', 'Tomcat']
            for server in web_servers:
                cmd = f'powershell -Command "Get-Process -Name {server}* -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    web_enc['details'].append(f"Server web trovato: {server}")

        return web_enc

    def _check_remote_access_encryption(self, target: Target) -> Dict:
        """
        Verifica la presenza di cifratura per accesso remoto (SSH, RDP).

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulla cifratura per accesso remoto
        """
        remote_enc = {
            'implemented': False,
            'ssh_encrypted': False,
            'rdp_encrypted': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Controlla SSH
            cmd = "ps aux | grep -v grep | grep sshd"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                remote_enc['details'].append("SSH server in esecuzione")

                # SSH è sempre cifrato, verifica algoritmi
                ssh_config = self.read_file_content(target, '/etc/ssh/sshd_config')
                if ssh_config:
                    # Verifica versione protocollo (solo SSH2 è sicuro)
                    if re.search(r'Protocol\s+2', ssh_config) or not re.search(r'Protocol\s+1', ssh_config):
                        remote_enc['ssh_encrypted'] = True
                        remote_enc['implemented'] = True
                        remote_enc['details'].append("SSH configurato con protocollo sicuro")

                    # Verifica algoritmi di cifratura
                    if re.search(r'Ciphers\s+.*aes.*,.*chacha20', ssh_config, re.IGNORECASE):
                        remote_enc['details'].append("SSH configurato con cifratura forte")
                else:
                    # Se non troviamo configurazioni specifiche, assumiamo che sia la configurazione predefinita
                    # che è generalmente sicura
                    remote_enc['ssh_encrypted'] = True
                    remote_enc['implemented'] = True
                    remote_enc['details'].append("SSH con configurazione predefinita (generalmente cifrato)")

            # Controlla VNC
            cmd = "ps aux | grep -v grep | grep vnc"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                remote_enc['details'].append("VNC server in esecuzione")

                # Controlla se VNC è configurato con SSL
                if 'ssl' in result['stdout'].lower() or 'tls' in result['stdout'].lower():
                    remote_enc['implemented'] = True
                    remote_enc['details'].append("VNC configurato con cifratura SSL/TLS")
                else:
                    remote_enc['details'].append("VNC potrebbe non essere cifrato")

        elif target.os_type.lower() == 'windows':
            # Controlla RDP
            cmd = 'powershell -Command "Get-ItemProperty -Path \'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\' -Name \'SecurityLayer\',\'MinEncryptionLevel\' | Format-List"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                remote_enc['details'].append("RDP configurato")

                # Verifica livello di sicurezza (2 = TLS, 1 = Negoziazione)
                if re.search(r'SecurityLayer\s*:\s*[12]', result['stdout']):
                    remote_enc['rdp_encrypted'] = True
                    remote_enc['implemented'] = True
                    remote_enc['details'].append("RDP configurato con cifratura TLS")

                # Verifica livello di cifratura (minimo 3 = Alto 128-bit)
                if re.search(r'MinEncryptionLevel\s*:\s*[34]', result['stdout']):
                    remote_enc['details'].append("RDP configurato con cifratura forte")

            # Controlla SSH su Windows
            cmd = 'powershell -Command "Get-Service -Name sshd -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq \'Running\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                remote_enc['details'].append("SSH server in esecuzione su Windows")
                remote_enc['ssh_encrypted'] = True
                remote_enc['implemented'] = True

        return remote_enc

    def _check_email_encryption(self, target: Target) -> Dict:
        """
        Verifica la presenza di cifratura per servizi email.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulla cifratura email
        """
        email_enc = {
            'implemented': False,
            'smtp_encrypted': False,
            'imap_encrypted': False,
            'pop3_encrypted': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Controlla SMTP
            smtp_servers = ['postfix', 'sendmail', 'exim']
            for server in smtp_servers:
                cmd = f"ps aux | grep -v grep | grep {server}"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    email_enc['details'].append(f"SMTP server trovato: {server}")

                    # Controlla configurazione TLS/SSL
                    if server == 'postfix':
                        config = self.read_file_content(target, '/etc/postfix/main.cf')
                        if config and re.search(r'smtpd_tls_security_level\s*=\s*encrypt', config):
                            email_enc['smtp_encrypted'] = True
                            email_enc['implemented'] = True
                            email_enc['details'].append("Postfix configurato con TLS obbligatorio")
                        elif config and re.search(r'smtpd_tls_security_level\s*=\s*may', config):
                            email_enc['details'].append("Postfix configurato con TLS opzionale")

                    elif server == 'exim':
                        config = self.read_file_content(target, '/etc/exim4/exim4.conf')
                        if config and ('tls_advertise_hosts' in config or 'tls_on_connect_ports' in config):
                            email_enc['smtp_encrypted'] = True
                            email_enc['implemented'] = True
                            email_enc['details'].append("Exim configurato con TLS")

            # Controlla IMAP/POP3
            imap_servers = ['dovecot', 'courier']
            for server in imap_servers:
                cmd = f"ps aux | grep -v grep | grep {server}"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip():
                    email_enc['details'].append(f"IMAP/POP3 server trovato: {server}")

                    # Controlla configurazione TLS/SSL
                    if server == 'dovecot':
                        config = self.read_file_content(target, '/etc/dovecot/dovecot.conf')
                        if config and 'ssl = yes' in config:
                            email_enc['imap_encrypted'] = True
                            email_enc['pop3_encrypted'] = True
                            email_enc['implemented'] = True
                            email_enc['details'].append("Dovecot configurato con SSL/TLS")

        elif target.os_type.lower() == 'windows':
            # Controlla Exchange
            cmd = 'powershell -Command "Get-Service -Name MSExchange* -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq \'Running\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                email_enc['details'].append("Microsoft Exchange in esecuzione")

                # Exchange moderno usa TLS per default
                email_enc['smtp_encrypted'] = True
                email_enc['imap_encrypted'] = True
                email_enc['pop3_encrypted'] = True
                email_enc['implemented'] = True
                email_enc['details'].append("Exchange moderno utilizza TLS per default")

            # Controlla SMTP
            cmd = 'powershell -Command "Get-Service -Name SMTPSVC -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq \'Running\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                email_enc['details'].append("SMTP Service in esecuzione")

                # Controlla certificato associato (semplificato)
                cmd = 'powershell -Command "Get-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object { $_.Subject -match \'mail|smtp|exchange\' } | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                    email_enc['smtp_encrypted'] = True
                    email_enc['implemented'] = True
                    email_enc['details'].append("Certificati per servizi email trovati")

        return email_enc

    def _check_vpn_encryption(self, target: Target) -> Dict:
        """
        Verifica la presenza di servizi VPN cifrati.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulla cifratura VPN
        """
        vpn_enc = {
            'implemented': False,
            'vpn_services': [],
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Controlla OpenVPN
            cmd = "ps aux | grep -v grep | grep openvpn"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                vpn_enc['implemented'] = True
                vpn_enc['vpn_services'].append('OpenVPN')
                vpn_enc['details'].append("OpenVPN in esecuzione")

                # Controlla configurazione
                config_paths = [
                    '/etc/openvpn/server.conf',
                    '/etc/openvpn/openvpn.conf'
                ]

                for path in config_paths:
                    content = self.read_file_content(target, path)
                    if content:
                        # Verifica cifratura
                        cipher_match = re.search(r'cipher\s+(\w+)', content)
                        if cipher_match:
                            vpn_enc['details'].append(f"OpenVPN configurato con cifratura {cipher_match.group(1)}")

            # Controlla IPsec/strongSwan
            cmd = "ps aux | grep -v grep | grep ipsec"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                vpn_enc['implemented'] = True
                vpn_enc['vpn_services'].append('IPsec')
                vpn_enc['details'].append("IPsec in esecuzione")

            # Controlla WireGuard
            cmd = "ps aux | grep -v grep | grep wireguard"
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip():
                vpn_enc['implemented'] = True
                vpn_enc['vpn_services'].append('WireGuard')
                vpn_enc['details'].append("WireGuard in esecuzione")

                # WireGuard usa cifratura forte per default
                vpn_enc['details'].append("WireGuard utilizza ChaCha20 per la cifratura")

        elif target.os_type.lower() == 'windows':
            # Controlla Windows VPN
            cmd = 'powershell -Command "Get-Service -Name RemoteAccess -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq \'Running\' } | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                vpn_enc['details'].append("Windows Remote Access (VPN) in esecuzione")

                # Windows VPN moderno utilizza protocolli sicuri
                vpn_enc['implemented'] = True
                vpn_enc['vpn_services'].append('Windows VPN')

            # Controlla OpenVPN su Windows
            cmd = 'powershell -Command "Get-Process -Name openvpn* -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                vpn_enc['implemented'] = True
                vpn_enc['vpn_services'].append('OpenVPN')
                vpn_enc['details'].append("OpenVPN in esecuzione")

            # Controlla altri software VPN
            vpn_software = ['Cisco AnyConnect', 'FortiClient', 'GlobalProtect', 'WireGuard', 'SoftEther']
            for software in vpn_software:
                cmd = f'powershell -Command "Get-ItemProperty HKLM:\\Software\\*\\*, HKLM:\\Software\\Wow6432Node\\*\\* | Where-Object {{ $_.DisplayName -match \'{software}\' }} | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    vpn_enc['implemented'] = True
                    vpn_enc['vpn_services'].append(software)
                    vpn_enc['details'].append(f"Software VPN trovato: {software}")

        return vpn_enc

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