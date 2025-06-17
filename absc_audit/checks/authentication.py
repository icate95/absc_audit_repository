"""
Authentication Checks - Implementazione dei controlli di autenticazione ABSC 2.x.

Questo modulo implementa i controlli relativi alle credenziali e
all'autenticazione secondo le specifiche ABSC 2.x.
"""

import time
import re
import os
from typing import Dict, List, Optional, Any, Tuple

from absc_audit.checks.base import BaseCheck
from absc_audit.storage.models import Target
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class PasswordPolicyCheck(BaseCheck):
    """
    Controllo per verificare le policy di password (ABSC 2.1.1-2.1.2).

    Verifica se sono in vigore policy per password robuste e se
    vengono forzati cambi di password periodici.
    """

    ID = "2.1.1-2.1.2"
    NAME = "Password Policy"
    DESCRIPTION = "Verifica delle policy di complessità password e del rinnovo periodico"
    QUESTION = "Sono in vigore policy per password robuste e cambi periodici?"
    POSSIBLE_ANSWERS = ["Sì completo", "Sì solo lunghezza/complessità", "Sì solo rinnovo", "No"]
    CATEGORY = "Authentication"
    PRIORITY = 2  # Media priorità

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Esegue il controllo sulle policy di password.

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

            # 1. Verifica le policy di complessità password
            password_complexity = self._check_password_complexity(target)

            # 2. Verifica le policy di rinnovo password
            password_expiration = self._check_password_expiration(target)

            # Compila i risultati
            result['raw_data'] = {
                'password_complexity': password_complexity,
                'password_expiration': password_expiration,
            }

            # Determina lo stato
            if password_complexity.get('implemented', False) and password_expiration.get('implemented', False):
                result['status'] = "Sì completo"
            elif password_complexity.get('implemented', False) and not password_expiration.get('implemented', False):
                result['status'] = "Sì solo lunghezza/complessità"
            elif not password_complexity.get('implemented', False) and password_expiration.get('implemented', False):
                result['status'] = "Sì solo rinnovo"
            else:
                result['status'] = "No"

            # Calcola punteggio
            result['score'] = self._calculate_custom_score(result['status'])

            # Aggiungi dettagli
            result['details'] = {
                'has_password_complexity': password_complexity,
                'has_password_expiration': password_expiration,
                'complexity_details': password_complexity,
                'expiration_details': password_expiration
            }

            # Aggiungi note
            if result['status'] == "No":
                result[
                    'notes'] = "Non sono state trovate policy di sicurezza per le password. È necessario implementare policy di complessità e scadenza."
            elif result['status'] == "Sì solo lunghezza/complessità":
                result[
                    'notes'] = "Sono presenti policy di complessità password, ma mancano policy di rinnovo periodico."
            elif result['status'] == "Sì solo rinnovo":
                result[
                    'notes'] = "Sono presenti policy di rinnovo periodico delle password, ma mancano policy di complessità."
            else:
                result[
                    'notes'] = "Le policy di password sono completamente implementate, con requisiti di complessità e rinnovo periodico."

        except Exception as e:
            self.log_error(target, e)
            result['status'] = "ERROR"
            result['details'] = {'error': str(e)}
            result['score'] = 0
        finally:
            duration = time.time() - start_time
            self.log_check_end(target, result['status'], duration)

        return result

    def _check_password_complexity(self, target: Target) -> Dict:
        """
        Verifica le policy di complessità password.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulle policy di complessità
        """
        complexity = {
            'min_length': 0,
            'requires_uppercase': False,
            'requires_lowercase': False,
            'requires_numbers': False,
            'requires_special_chars': False,
            'implemented': False
        }

        if target.os_type.lower() == 'windows':
            # Controlla le policy di password tramite PowerShell
            cmd = 'powershell -Command "Get-ADDefaultDomainPasswordPolicy | Format-List MinPasswordLength, ComplexityEnabled"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout']:
                # Estrai la lunghezza minima
                min_length_match = re.search(r'MinPasswordLength\s*:\s*(\d+)', result['stdout'])
                if min_length_match:
                    complexity['min_length'] = int(min_length_match.group(1))

                # Verifica se la complessità è abilitata
                complexity_match = re.search(r'ComplexityEnabled\s*:\s*(True|False)', result['stdout'])
                if complexity_match and complexity_match.group(1) == 'True':
                    complexity['requires_uppercase'] = True
                    complexity['requires_lowercase'] = True
                    complexity['requires_numbers'] = True
                    complexity['requires_special_chars'] = True

            # Controlla anche le impostazioni di sicurezza locali
            cmd = 'powershell -Command "($secpol = Get-Content C:\\Windows\\security\\database\\secedit.sdb | Out-String); $secpol"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout']:
                # Analizza le impostazioni di sicurezza...
                pass

        elif target.os_type.lower() in ['linux', 'unix']:
            # Controlla le configurazioni PAM
            pam_files = [
                '/etc/pam.d/common-password',
                '/etc/pam.d/system-auth',
                '/etc/security/pwquality.conf',
                '/etc/security/pwquality.conf.d/'
            ]

            for file_path in pam_files:
                content = self.read_file_content(target, file_path)
                if content:
                    # Verifica parametri minimo di lunghezza
                    min_length_match = re.search(r'minlen=(\d+)', content)
                    if min_length_match:
                        complexity['min_length'] = int(min_length_match.group(1))

                    # Verifica requisiti di complessità
                    if 'ucredit' in content or 'lcredit' in content or 'dcredit' in content or 'ocredit' in content:
                        if 'ucredit=-1' in content or 'ucredit<0' in content:
                            complexity['requires_uppercase'] = True
                        if 'lcredit=-1' in content or 'lcredit<0' in content:
                            complexity['requires_lowercase'] = True
                        if 'dcredit=-1' in content or 'dcredit<0' in content:
                            complexity['requires_numbers'] = True
                        if 'ocredit=-1' in content or 'ocredit<0' in content:
                            complexity['requires_special_chars'] = True

        # Determina se le policy di complessità sono implementate
        if complexity['min_length'] >= 8 and (
                complexity['requires_uppercase'] or
                complexity['requires_lowercase'] or
                complexity['requires_numbers'] or
                complexity['requires_special_chars']):
            complexity['implemented'] = True

        return complexity

    def _check_password_expiration(self, target: Target) -> Dict:
        """
        Verifica le policy di scadenza password.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sulle policy di scadenza
        """
        expiration = {
            'max_days': 0,
            'implemented': False
        }

        if target.os_type.lower() == 'windows':
            # Controlla le policy di scadenza tramite PowerShell
            cmd = 'powershell -Command "Get-ADDefaultDomainPasswordPolicy | Format-List MaxPasswordAge"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout']:
                # Estrai il periodo massimo
                max_days_match = re.search(r'MaxPasswordAge\s*:\s*(\d+)', result['stdout'])
                if max_days_match:
                    expiration['max_days'] = int(max_days_match.group(1))

        elif target.os_type.lower() in ['linux', 'unix']:
            # Controlla il file login.defs
            content = self.read_file_content(target, '/etc/login.defs')
            if content:
                max_days_match = re.search(r'PASS_MAX_DAYS\s+(\d+)', content)
                if max_days_match:
                    expiration['max_days'] = int(max_days_match.group(1))

        # Determina se le policy di scadenza sono implementate
        if expiration['max_days'] > 0 and expiration['max_days'] <= 90:
            expiration['implemented'] = True

        return expiration

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
        elif status == "Sì solo lunghezza/complessità":
            return 70
        elif status == "Sì solo rinnovo":
            return 60
        elif status == "No":
            return 0
        else:
            return 0


class AdminAccountsCheck(BaseCheck):
    """
    Controllo per verificare la gestione degli account amministrativi (ABSC 2.4.1-2.4.2).

    Verifica se gli account con privilegi amministrativi sono gestiti secondo
    il principio del privilegio minimo.
    """

    ID = "2.4.1-2.4.2"
    NAME = "Account Amministrativi"
    DESCRIPTION = "Verifica della gestione degli account con privilegi amministrativi"
    QUESTION = "Gli account amministrativi sono gestiti con privilegi minimi e inventariati?"
    POSSIBLE_ANSWERS = ["Sì completo", "Sì solo inventario", "Sì solo minimi privilegi", "No"]
    CATEGORY = "Authentication"
    PRIORITY = 2  # Media priorità

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Esegue il controllo sugli account amministrativi.

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

            # 1. Verifica l'inventario degli account amministrativi
            admin_inventory = self._check_admin_inventory(target)

            # 2. Verifica l'applicazione del principio del privilegio minimo
            least_privilege = self._check_least_privilege(target)

            # Compila i risultati
            result['raw_data'] = {
                'admin_inventory': admin_inventory,
                'least_privilege': least_privilege,
            }

            # Determina lo stato
            if admin_inventory and least_privilege:
                result['status'] = "Sì completo"
            elif admin_inventory and not least_privilege:
                result['status'] = "Sì solo inventario"
            elif not admin_inventory and least_privilege:
                result['status'] = "Sì solo minimi privilegi"
            else:
                result['status'] = "No"

            # Calcola punteggio
            result['score'] = self._calculate_custom_score(result['status'])

            # Aggiungi dettagli
            result['details'] = {
                'has_admin_inventory': admin_inventory,
                'has_least_privilege': least_privilege,
                'inventory_details': admin_inventory,
                'privilege_details': least_privilege
            }

            # Aggiungi note
            if result['status'] == "No":
                result[
                    'notes'] = "Non è stata trovata una gestione adeguata degli account amministrativi. È necessario implementare un inventario e applicare il principio del privilegio minimo."
            elif result['status'] == "Sì solo inventario":
                result[
                    'notes'] = "Esiste un inventario degli account amministrativi, ma non viene applicato il principio del privilegio minimo."
            elif result['status'] == "Sì solo minimi privilegi":
                result[
                    'notes'] = "Viene applicato il principio del privilegio minimo, ma manca un inventario formale degli account amministrativi."
            else:
                result[
                    'notes'] = "Gli account amministrativi sono gestiti correttamente, con un inventario completo e l'applicazione del principio del privilegio minimo."

        except Exception as e:
            self.log_error(target, e)
            result['status'] = "ERROR"
            result['details'] = {'error': str(e)}
            result['score'] = 0
        finally:
            duration = time.time() - start_time
            self.log_check_end(target, result['status'], duration)

        return result

    def _check_admin_inventory(self, target: Target) -> Dict:
        """
        Verifica la presenza di un inventario degli account amministrativi.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sull'inventario
        """
        inventory = {
            'found': False,
            'location': None,
            'last_updated': None,
            'admin_count': 0
        }

        # Verifica file comuni per l'inventario
        inventory_files = [
            '/etc/security/admin_inventory.json',
            '/etc/security/admin_users.txt',
            '/opt/security/admin_accounts.json',
            'C:\\ProgramData\\Security\\AdminAccounts.json',
            'C:\\ProgramData\\Security\\AdminInventory.txt'
        ]

        for file_path in inventory_files:
            if self.check_file_exists(target, file_path):
                inventory['found'] = True
                inventory['location'] = file_path

                # Ottieni la data di ultima modifica
                if target.os_type.lower() in ['linux', 'unix']:
                    cmd = f'stat -c %Y "{file_path}"'
                    result = self.execute_command(target, cmd)
                    if result['exit_code'] == 0 and result['stdout']:
                        try:
                            timestamp = int(result['stdout'].strip())
                            inventory['last_updated'] = timestamp
                        except ValueError:
                            pass
                else:  # Windows
                    cmd = f'powershell -Command "(Get-Item -Path \'{file_path}\').LastWriteTime.ToString(\'yyyy-MM-dd\')"'
                    result = self.execute_command(target, cmd)
                    if result['exit_code'] == 0 and result['stdout']:
                        inventory['last_updated'] = result['stdout'].strip()

                # Conta gli account amministrativi
                content = self.read_file_content(target, file_path)
                if content:
                    lines = content.strip().split('\n')
                    inventory['admin_count'] = len(lines)

                return inventory

        # Se non è stato trovato un file, controlla i gruppi di amministratori
        if target.os_type.lower() == 'windows':
            # Controlla i membri del gruppo Administrators
            cmd = 'powershell -Command "Get-LocalGroupMember -Group Administrators | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout']:
                try:
                    count = int(result['stdout'].strip())
                    if count > 0:
                        inventory['admin_count'] = count
                        inventory['found'] = True
                        inventory['location'] = "Local Administrators Group"
                except ValueError:
                    pass
        elif target.os_type.lower() in ['linux', 'unix']:
            # Controlla i membri del gruppo sudo e wheel
            for group in ['sudo', 'wheel', 'admin']:
                cmd = f'grep "{group}" /etc/group | cut -d: -f4 | tr "," "\\n" | wc -l'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout']:
                    try:
                        count = int(result['stdout'].strip())
                        if count > 0:
                            inventory['admin_count'] += count
                            inventory['found'] = True
                            if not inventory['location']:
                                inventory['location'] = f"{group} Group"
                            else:
                                inventory['location'] += f", {group} Group"
                    except ValueError:
                        pass

        return inventory

    def _check_least_privilege(self, target: Target) -> Dict:
        """
        Verifica l'applicazione del principio del privilegio minimo.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sui privilegi
        """
        privileges = {
            'implemented': False,
            'evidence': []
        }

        if target.os_type.lower() == 'windows':
            # Verifica User Rights Assignment tramite secedit
            cmd = 'powershell -Command "secedit /export /cfg C:\\Windows\\Temp\\secpol.cfg /quiet; Get-Content C:\\Windows\\Temp\\secpol.cfg | Select-String -Pattern \"SeDebug|SeTakeOwnership|SeBackup|SeRestore|SeLoadDriver\""'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout']:
                privileges['evidence'].append("Restricted privileged rights assignments found")

                # Se trovate assegnazioni restrittive, presumiamo l'implementazione
                if len(result['stdout'].strip().split('\n')) >= 3:
                    privileges['implemented'] = True

            # Verifica l'uso di account amministrativi separati
            cmd = 'powershell -Command "Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.Name -ne \'Administrator\'} | Where-Object {net localgroup Administrators $_.Name | Select-String -Quiet \'is a member\'} | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout']:
                try:
                    count = int(result['stdout'].strip())
                    if count > 0:
                        privileges['evidence'].append(f"Found {count} non-default administrator accounts")
                        privileges['implemented'] = True
                except ValueError:
                    pass

        elif target.os_type.lower() in ['linux', 'unix']:
            # Verifica la configurazione di sudo
            sudo_conf = self.read_file_content(target, '/etc/sudoers')

            if sudo_conf and re.search(r'NOPASSWD:|ALL=\(ALL\)', sudo_conf) is None:
                privileges['evidence'].append("Restrictive sudo configuration found")
                privileges['implemented'] = True

            # Verifica l'uso di gruppi con privilegi specifici
            for file_path in ['/etc/group', '/etc/gshadow']:
                content = self.read_file_content(target, file_path)
                if content:
                    specific_groups = re.findall(r'(sudo|wheel|admin|docker|disk|lxd):', content)
                    if len(specific_groups) > 1:
                        privileges['evidence'].append(f"Found specific privilege groups: {', '.join(specific_groups)}")
                        privileges['implemented'] = True

        return privileges

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
        elif status == "Sì solo inventario":
            return 60
        elif status == "Sì solo minimi privilegi":
            return 70
        elif status == "No":
            return 0
        else:
            return 0