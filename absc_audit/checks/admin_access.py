"""
Admin Access Checks - Implementazione dei controlli di accesso amministrativo ABSC 5.x.

Questo modulo implementa i controlli relativi all'accesso amministrativo
secondo le specifiche ABSC 5.x.
"""

import time
import re
import os
from typing import Dict, List, Optional, Any, Tuple

from absc_audit.checks.base import BaseCheck
from absc_audit.storage.models import Target
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class AdminAccessControlCheck(BaseCheck):
    """
    Controllo per verificare le politiche di accesso amministrativo (ABSC 5.1.1-5.1.2).

    Verifica se sono implementati meccanismi per l'utilizzo delle utenze amministrative
    solo per le operazioni che richiedono privilegi elevati.
    """

    ID = "5.1.1-5.1.2"
    NAME = "Utilizzo privilegiato delle utenze amministrative"
    DESCRIPTION = "Verifica dei meccanismi di controllo per l'utilizzo delle utenze amministrative"
    QUESTION = "Esistono meccanismi per limitare l'utilizzo delle utenze amministrative alle sole operazioni che richiedono privilegi elevati?"
    POSSIBLE_ANSWERS = ["Sì con controllo accessi", "Sì base", "No"]
    CATEGORY = "AdminAccess"
    PRIORITY = 2  # Media priorità

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Esegue il controllo sui meccanismi di accesso amministrativo.

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

            # 1. Verifica l'utilizzo di meccanismi di privilegi elevati
            privilege_mechanisms = self._check_privilege_mechanisms(target)

            # 2. Verifica la presenza di controlli di accesso avanzati
            access_controls = self._check_access_controls(target)

            # Compila i risultati
            result['raw_data'] = {
                'privilege_mechanisms': privilege_mechanisms,
                'access_controls': access_controls
            }

            # Determina lo stato
            if privilege_mechanisms.get('implemented', False):
                if access_controls.get('implemented', False):
                    result['status'] = "Sì con controllo accessi"
                else:
                    result['status'] = "Sì base"
            else:
                result['status'] = "No"

            # Calcola punteggio
            result['score'] = self._calculate_custom_score(result['status'])

            # Aggiungi dettagli
            result['details'] = {
                'has_privilege_mechanisms': privilege_mechanisms.get('implemented', False),
                'has_access_controls': access_controls.get('implemented', False),
                'privilege_mechanisms_details': privilege_mechanisms,
                'access_controls_details': access_controls
            }

            # Aggiungi note
            if result['status'] == "No":
                result[
                    'notes'] = "Non sono stati trovati meccanismi per limitare l'utilizzo delle utenze amministrative. È necessario implementare controlli per l'elevazione dei privilegi."
            elif result['status'] == "Sì base":
                result[
                    'notes'] = "Sono implementati meccanismi di base per l'elevazione dei privilegi, ma mancano controlli di accesso avanzati."
            else:
                result[
                    'notes'] = "Sono implementati sia meccanismi per l'elevazione dei privilegi che controlli di accesso avanzati, limitando efficacemente l'utilizzo delle utenze amministrative alle operazioni necessarie."

        except Exception as e:
            self.log_error(target, e)
            result['status'] = "ERROR"
            result['details'] = {'error': str(e)}
            result['score'] = 0
        finally:
            duration = time.time() - start_time
            self.log_check_end(target, result['status'], duration)

        return result

    def _check_privilege_mechanisms(self, target: Target) -> Dict:
        """
        Verifica la presenza di meccanismi per l'elevazione dei privilegi.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sui meccanismi trovati
        """
        mechanisms = {
            'implemented': False,
            'sudo_configured': False,
            'uac_configured': False,
            'privilege_cmds_found': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica la presenza e configurazione di sudo
            sudo_exists = self.check_file_exists(target, '/etc/sudoers')
            if sudo_exists:
                mechanisms['sudo_configured'] = True
                mechanisms['details'].append("Sistema sudo configurato")

                # Controlla se sudo è configurato correttamente
                sudo_content = self.read_file_content(target, '/etc/sudoers')
                if sudo_content:
                    # Verifica se ci sono regole specifiche che non danno accesso illimitato
                    if not re.search(r'ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL', sudo_content) or \
                            re.search(r'Cmnd_Alias', sudo_content):
                        mechanisms['details'].append("Sudo configurato con regole specifiche")
                        mechanisms['implemented'] = True

            # Verifica i permessi sui comandi sensibili
            sensitive_dirs = ['/bin', '/sbin', '/usr/bin', '/usr/sbin']
            for directory in sensitive_dirs:
                if self.check_file_exists(target, directory):
                    cmd = f"find {directory} -perm -4000 -type f | wc -l"
                    result = self.execute_command(target, cmd)
                    if result['exit_code'] == 0 and result['stdout']:
                        try:
                            count = int(result['stdout'].strip())
                            if count > 0 and count < 20:  # Un numero ragionevole di comandi SUID
                                mechanisms['privilege_cmds_found'] = True
                                mechanisms['details'].append(f"Trovati {count} comandi SUID in {directory}")
                                mechanisms['implemented'] = True
                            elif count >= 20:
                                mechanisms['details'].append(
                                    f"Trovati troppi comandi SUID ({count}) in {directory}, potenziale rischio di sicurezza")
                        except ValueError:
                            pass

        elif target.os_type.lower() == 'windows':
            # Verifica la configurazione di UAC
            cmd = 'powershell -Command "Get-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" -Name \"EnableLUA\" | Select-Object -ExpandProperty EnableLUA"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                mechanisms['uac_configured'] = True
                mechanisms['details'].append("UAC (User Account Control) è attivo")

                # Verifica il livello di UAC
                cmd = 'powershell -Command "Get-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" -Name \"ConsentPromptBehaviorAdmin\" | Select-Object -ExpandProperty ConsentPromptBehaviorAdmin"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() in ['1', '2', '5']:
                    mechanisms['details'].append(
                        f"UAC configurato con livello di sicurezza adeguato: {result['stdout'].strip()}")
                    mechanisms['implemented'] = True

            # Verifica l'uso di RunAs
            cmd = 'powershell -Command "Get-Command RunAs -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                mechanisms['details'].append("Comando RunAs disponibile per l'elevazione dei privilegi")
                mechanisms['privilege_cmds_found'] = True
                mechanisms['implemented'] = True

        return mechanisms

    def _check_access_controls(self, target: Target) -> Dict:
        """
        Verifica la presenza di controlli di accesso avanzati.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sui controlli trovati
        """
        controls = {
            'implemented': False,
            'rbac_implemented': False,
            'auditing_enabled': False,
            'event_logging': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica la presenza di audit e logging
            if self.check_file_exists(target, '/etc/audit/auditd.conf'):
                cmd = "systemctl is-active auditd"
                result = self.execute_command(target, cmd)
                if result['exit_code'] == 0 and result['stdout'].strip() == 'active':
                    controls['auditing_enabled'] = True
                    controls['details'].append("Servizio auditd attivo")

                    # Verifica regole di audit per comandi privilegiati
                    if self.check_file_exists(target, '/etc/audit/audit.rules'):
                        audit_rules = self.read_file_content(target, '/etc/audit/audit.rules')
                        if audit_rules and re.search(r'-a\s+always,exit\s+-F\s+path=.*sudo', audit_rules):
                            controls['details'].append("Regole di audit configurate per comandi privilegiati")
                            controls['implemented'] = True

            # Verifica logging di sistema
            if self.check_file_exists(target, '/var/log/auth.log') or self.check_file_exists(target, '/var/log/secure'):
                controls['event_logging'] = True
                controls['details'].append("Logging degli eventi di autenticazione attivo")

            # Verifica RBAC con SELinux/AppArmor
            selinux_enabled = False
            apparmor_enabled = False

            cmd = "getenforce 2>/dev/null || echo Disabled"
            result = self.execute_command(target, cmd)
            if result['exit_code'] == 0 and result['stdout'].strip() in ['Enforcing', 'Permissive']:
                selinux_enabled = True
                controls['rbac_implemented'] = True
                controls['details'].append(f"SELinux attivo in modalità {result['stdout'].strip()}")
                controls['implemented'] = True

            cmd = "aa-status 2>/dev/null || echo Disabled"
            result = self.execute_command(target, cmd)
            if result['exit_code'] == 0 and 'apparmor module is loaded' in result['stdout']:
                apparmor_enabled = True
                controls['rbac_implemented'] = True
                controls['details'].append("AppArmor attivo")
                controls['implemented'] = True

        elif target.os_type.lower() == 'windows':
            # Verifica auditing di Windows
            cmd = 'powershell -Command "auditpol /get /category:* | Select-String \"Account Logon\"|Select-String \"Success and Failure\"|Measure-Object|Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                controls['auditing_enabled'] = True
                controls['details'].append("Auditing di Windows configurato per eventi di accesso")
                controls['implemented'] = True

            # Verifica logging degli eventi
            cmd = 'powershell -Command "Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                controls['event_logging'] = True
                controls['details'].append("Logging degli eventi di sicurezza attivo")
                controls['implemented'] = True

            # Verifica controlli di accesso avanzati (AppLocker/etc)
            cmd = 'powershell -Command "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                controls['rbac_implemented'] = True
                controls['details'].append("AppLocker configurato per il controllo delle applicazioni")
                controls['implemented'] = True

        return controls

    def _calculate_custom_score(self, status: str) -> float:
        """
        Calcola un punteggio personalizzato in base allo stato.

        Args:
            status: Stato del controllo

        Returns:
            Punteggio da 0 a 100
        """
        if status == "Sì con controllo accessi":
            return 100
        elif status == "Sì base":
            return 70
        elif status == "No":
            return 0
        else:
            return 0


class AdminRemoteAccessCheck(BaseCheck):
    """
    Controllo per verificare l'accesso amministrativo remoto (ABSC 5.7.1-5.7.4).

    Verifica se sono implementati meccanismi di sicurezza per l'accesso remoto con account amministrativi.
    """

    ID = "5.7.1-5.7.4"
    NAME = "Accesso amministrativo remoto"
    DESCRIPTION = "Verifica dei meccanismi di sicurezza per l'accesso amministrativo remoto"
    QUESTION = "Sono implementati meccanismi di sicurezza specifici per l'accesso remoto con account amministrativi?"
    POSSIBLE_ANSWERS = ["Sì completo", "Sì parziale", "No"]
    CATEGORY = "AdminAccess"
    PRIORITY = 2  # Media priorità

    def run(self, target: Target, params: Dict = None) -> Dict:
        """
        Esegue il controllo sull'accesso amministrativo remoto.

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

            # 1. Verifica la sicurezza dei protocolli di accesso remoto
            secure_protocols = self._check_secure_protocols(target)

            # 2. Verifica l'autenticazione a più fattori per l'accesso remoto
            multi_factor = self._check_multi_factor(target)

            # 3. Verifica il monitoraggio specifico per l'accesso remoto
            remote_monitoring = self._check_remote_monitoring(target)

            # Compila i risultati
            result['raw_data'] = {
                'secure_protocols': secure_protocols,
                'multi_factor': multi_factor,
                'remote_monitoring': remote_monitoring
            }

            # Determina lo stato
            if secure_protocols.get('implemented', False) and multi_factor.get('implemented',
                                                                               False) and remote_monitoring.get(
                    'implemented', False):
                result['status'] = "Sì completo"
            elif secure_protocols.get('implemented', False) and (
                    multi_factor.get('implemented', False) or remote_monitoring.get('implemented', False)):
                result['status'] = "Sì parziale"
            else:
                result['status'] = "No"

            # Calcola punteggio
            result['score'] = self._calculate_custom_score(result['status'])

            # Aggiungi dettagli
            result['details'] = {
                'has_secure_protocols': secure_protocols.get('implemented', False),
                'has_multi_factor': multi_factor.get('implemented', False),
                'has_remote_monitoring': remote_monitoring.get('implemented', False),
                'secure_protocols_details': secure_protocols,
                'multi_factor_details': multi_factor,
                'remote_monitoring_details': remote_monitoring
            }

            # Aggiungi note
            if result['status'] == "No":
                result[
                    'notes'] = "Non sono stati trovati meccanismi di sicurezza adeguati per l'accesso amministrativo remoto. È necessario implementare protocolli sicuri, autenticazione a più fattori e monitoraggio specifico."
            elif result['status'] == "Sì parziale":
                result[
                    'notes'] = "Sono implementati alcuni meccanismi di sicurezza per l'accesso amministrativo remoto, ma la protezione non è completa."
            else:
                result[
                    'notes'] = "Sono implementati meccanismi di sicurezza completi per l'accesso amministrativo remoto, inclusi protocolli sicuri, autenticazione a più fattori e monitoraggio specifico."

        except Exception as e:
            self.log_error(target, e)
            result['status'] = "ERROR"
            result['details'] = {'error': str(e)}
            result['score'] = 0
        finally:
            duration = time.time() - start_time
            self.log_check_end(target, result['status'], duration)

        return result

    def _check_secure_protocols(self, target: Target) -> Dict:
        """
        Verifica l'utilizzo di protocolli sicuri per l'accesso remoto.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sui protocolli trovati
        """
        protocols = {
            'implemented': False,
            'ssh_secure': False,
            'rdp_secure': False,
            'vpn_available': False,
            'insecure_protocols': [],
            'secure_protocols': [],
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica configurazione SSH
            if self.check_file_exists(target, '/etc/ssh/sshd_config'):
                ssh_config = self.read_file_content(target, '/etc/ssh/sshd_config')

                if ssh_config:
                    # Verifica che PermitRootLogin sia disabilitato o limitato
                    root_login_match = re.search(r'^\s*PermitRootLogin\s+(\w+)', ssh_config, re.MULTILINE)
                    if root_login_match and root_login_match.group(1) in ['no', 'prohibit-password']:
                        protocols['details'].append("SSH configurato per impedire login root diretto")
                        protocols['secure_protocols'].append("SSH (root login disabilitato)")

                    # Verifica che PasswordAuthentication sia disabilitato
                    pass_auth_match = re.search(r'^\s*PasswordAuthentication\s+(\w+)', ssh_config, re.MULTILINE)
                    if pass_auth_match and pass_auth_match.group(1) == 'no':
                        protocols['details'].append("SSH configurato per utilizzare solo autenticazione a chiave")
                        if "SSH" not in protocols['secure_protocols']:
                            protocols['secure_protocols'].append("SSH (solo chiavi)")

                    # Verifica la versione del protocollo SSH
                    proto_match = re.search(r'^\s*Protocol\s+(\d+)', ssh_config, re.MULTILINE)
                    if proto_match and proto_match.group(1) == '2':
                        protocols['details'].append("SSH configurato per utilizzare solo il protocollo v2")
                        if "SSH" not in protocols['secure_protocols']:
                            protocols['secure_protocols'].append("SSH (protocollo v2)")

                    # Se sono presenti almeno 2 configurazioni di sicurezza, consideriamo SSH sicuro
                    if len([d for d in protocols['details'] if 'SSH' in d]) >= 2:
                        protocols['ssh_secure'] = True
                        protocols['implemented'] = True

            # Verifica presenza di protocolli insicuri
            insecure_services = ['telnetd', 'rsh', 'rlogin']
            for service in insecure_services:
                cmd = f"ps -ef | grep -v grep | grep {service} | wc -l"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    protocols['insecure_protocols'].append(service)
                    protocols['implemented'] = False  # Annulla l'implementazione sicura se ci sono servizi insicuri

            # Verifica presenza di VPN
            vpn_services = ['openvpn', 'wireguard', 'ipsec', 'strongswan']
            for service in vpn_services:
                cmd = f"ps -ef | grep -v grep | grep {service} | wc -l"
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    protocols['vpn_available'] = True
                    protocols['secure_protocols'].append(service.upper())
                    protocols['details'].append(f"Servizio VPN {service} attivo")
                    protocols['implemented'] = True

        elif target.os_type.lower() == 'windows':
            # Verifica configurazione RDP
            cmd = 'powershell -Command "Get-ItemProperty -Path \"HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" -Name \"SecurityLayer\" | Select-Object -ExpandProperty SecurityLayer"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() in ['1', '2']:
                protocols['rdp_secure'] = True
                protocols['secure_protocols'].append("RDP (SSL/TLS)")
                protocols['details'].append("RDP configurato con livello di sicurezza SSL/TLS")
                protocols['implemented'] = True

            # Verifica NLA (Network Level Authentication)
            cmd = 'powershell -Command "Get-ItemProperty -Path \"HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" -Name \"UserAuthentication\" | Select-Object -ExpandProperty UserAuthentication"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                if not protocols['rdp_secure']:
                    protocols['rdp_secure'] = True
                protocols['secure_protocols'].append("RDP (NLA)")
                protocols['details'].append("RDP configurato con autenticazione a livello di rete (NLA)")
                protocols['implemented'] = True

            # Verifica presenza di VPN
            vpn_services = ['RasMan', 'SstpSvc', 'WinVPN', 'IKEEXT']
            for service in vpn_services:
                cmd = f'powershell -Command "Get-Service -Name {service} -ErrorAction SilentlyContinue | Where-Object {{$_.Status -eq \'Running\'}} | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                    protocols['vpn_available'] = True
                    protocols['secure_protocols'].append("VPN")
                    protocols['details'].append(f"Servizio VPN {service} attivo")
                    protocols['implemented'] = True
                    break

            # Verifica se RDP è disabilitato (che è ancora più sicuro)
            cmd = 'powershell -Command "Get-ItemProperty -Path \"HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\" -Name \"fDenyTSConnections\" | Select-Object -ExpandProperty fDenyTSConnections"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                protocols['details'].append("RDP disabilitato")
                if not protocols['secure_protocols'] and not protocols['vpn_available']:
                    protocols['implemented'] = False  # Non c'è RDP e non c'è VPN, non c'è modo di accedere remotamente

            # Verifica presenza di protocolli insicuri (Telnet, ecc.)
            insecure_services = ['TlntSvr', 'SharedAccess']
            for service in insecure_services:
                cmd = f'powershell -Command "Get-Service -Name {service} -ErrorAction SilentlyContinue | Where-Object {{$_.Status -eq \'Running\'}} | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                    protocols['insecure_protocols'].append(service)
                    protocols['implemented'] = False  # Annulla l'implementazione sicura se ci sono servizi insicuri

        # Se ci sono protocolli insicuri attivi, questa è una nota importante
        if protocols['insecure_protocols']:
            protocols['details'].append(
                f"Trovati protocolli insicuri attivi: {', '.join(protocols['insecure_protocols'])}")

        return protocols

    def _check_multi_factor(self, target: Target) -> Dict:
        """
        Verifica l'utilizzo di autenticazione a più fattori per l'accesso remoto.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sull'autenticazione a più fattori
        """
        mfa = {
            'implemented': False,
            'pam_mfa': False,
            'smart_card': False,
            'totp': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica moduli PAM per MFA
            pam_configs = [
                '/etc/pam.d/sshd',
                '/etc/pam.d/login',
                '/etc/pam.d/common-auth',
                '/etc/pam.d/system-auth'
            ]

            for config in pam_configs:
                content = self.read_file_content(target, config)
                if content:
                    # Verifica Google Authenticator o altri TOTP
                    if re.search(r'pam_google_authenticator|libpam-google-authenticator|pam_oath', content):
                        mfa['totp'] = True
                        mfa['pam_mfa'] = True
                        mfa['details'].append(f"TOTP configurato in {config}")
                        mfa['implemented'] = True

                    # Verifica Yubikey o altre chiavi hardware
                    if re.search(r'pam_yubico|pam_u2f', content):
                        mfa['pam_mfa'] = True
                        mfa['details'].append(f"Autenticazione con chiave hardware configurata in {config}")
                        mfa['implemented'] = True

                    # Verifica smart card
                    if re.search(r'pam_pkcs11|pam_p11|pam_smart_card', content):
                        mfa['smart_card'] = True
                        mfa['pam_mfa'] = True
                        mfa['details'].append(f"Autenticazione con smart card configurata in {config}")
                        mfa['implemented'] = True

            # Verifica presenza di file di configurazione per MFA
            mfa_configs = [
                '~/.google_authenticator',
                '/etc/yubikey_mappings',
                '/etc/pam_u2f.conf'
            ]

            for config in mfa_configs:
                if self.check_file_exists(target, config):
                    mfa['details'].append(f"Trovato file di configurazione MFA: {config}")
                    mfa['implemented'] = True

        elif target.os_type.lower() == 'windows':
            # Verifica Windows Hello for Business (biometrico o PIN)
            cmd = 'powershell -Command "Get-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\PassportForWork\" -Name \"Enabled\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Enabled"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == '1':
                mfa['details'].append("Windows Hello for Business abilitato")
                mfa['implemented'] = True

            # Verifica Smart Card per l'accesso remoto
            cmd = 'powershell -Command "Get-WmiObject -Class Win32_TSAccount -Filter \'TerminalName=\"RDP-Tcp\"\' -Namespace root\\CIMV2\\TerminalServices | Select-Object -ExpandProperty SmartCardLogonRequired"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == 'True':
                mfa['smart_card'] = True
                mfa['details'].append("RDP richiede smart card per l'accesso")
                mfa['implemented'] = True

            # Verifica policy del dominio per MFA
            cmd = 'powershell -Command "Get-ADDefaultDomainPasswordPolicy 2>$null | Out-Null; if ($?) { Write-Output \'Domain\' } else { Write-Output \'Standalone\' }"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() == 'Domain':
                # È un controller di dominio o un client di dominio, verifica policy MFA
                cmd = 'powershell -Command "Import-Module ActiveDirectory 2>$null; if (Get-Command \'Get-ADFineGrainedPasswordPolicy\' -ErrorAction SilentlyContinue) { Get-ADFineGrainedPasswordPolicy -Filter * | Measure-Object | Select-Object -ExpandProperty Count } else { Write-Output \'0\' }"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    mfa['details'].append("Policy di sicurezza granulari trovate nel dominio")
                    mfa['implemented'] = True

                # Verifica software MFA di terze parti
            mfa_software = ['Duo', 'RSA', 'Okta', 'Symantec VIP', 'Auth0', 'MicrosoftAuthenticator']
            for software in mfa_software:
                cmd = f'powershell -Command "Get-ItemProperty HKLM:\\Software\\*\\*, HKLM:\\Software\\Wow6432Node\\*\\* | Where-Object {{ $_.DisplayName -match \'{software}\' }} | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    mfa['details'].append(f"Software MFA trovato: {software}")
                    mfa['totp'] = True
                    mfa['implemented'] = True

        return mfa

    def _check_remote_monitoring(self, target: Target) -> Dict:
        """
        Verifica la presenza di monitoraggio specifico per l'accesso remoto.

        Args:
            target: Target su cui verificare

        Returns:
            Dizionario con informazioni sul monitoraggio
        """
        monitoring = {
            'implemented': False,
            'session_logging': False,
            'access_logging': False,
            'alert_system': False,
            'details': []
        }

        if target.os_type.lower() in ['linux', 'unix']:
            # Verifica logging SSH
            ssh_config = self.read_file_content(target, '/etc/ssh/sshd_config')
            if ssh_config:
                # Verifica log level
                log_level_match = re.search(r'^\s*LogLevel\s+(\w+)', ssh_config, re.MULTILINE)
                if log_level_match and log_level_match.group(1) in ['VERBOSE', 'DEBUG', 'INFO']:
                    monitoring['access_logging'] = True
                    monitoring['details'].append(f"SSH configurato con livello di log {log_level_match.group(1)}")
                    monitoring['implemented'] = True

            # Verifica presenza di PAM per logging
            pam_configs = ['/etc/pam.d/sshd', '/etc/pam.d/login']
            for config in pam_configs:
                content = self.read_file_content(target, config)
                if content and re.search(r'pam_tty_audit|pam_tty_audit.so', content):
                    monitoring['session_logging'] = True
                    monitoring['details'].append(f"Logging sessione TTY configurato in {config}")
                    monitoring['implemented'] = True

            # Verifica presenza di script/tool per monitoraggio
            monitoring_tools = [
                '/usr/local/bin/ssh-alert.sh',
                '/etc/profile.d/ssh-alert.sh',
                '/usr/local/bin/ssh-monitor.py',
                '/opt/security/remote-monitor.sh'
            ]

            for tool in monitoring_tools:
                if self.check_file_exists(target, tool):
                    content = self.read_file_content(target, tool)
                    if content and ('mail' in content or 'alert' in content or 'notify' in content):
                        monitoring['alert_system'] = True
                        monitoring['details'].append(f"Script di monitoraggio con avvisi trovato: {tool}")
                        monitoring['implemented'] = True

            # Verifica auditd per SSH
            if self.check_file_exists(target, '/etc/audit/rules.d/sshd.rules'):
                monitoring['access_logging'] = True
                monitoring['details'].append("Regole audit specifiche per SSH trovate")
                monitoring['implemented'] = True

            # Verifica log di accesso remoto
            log_dirs = ['/var/log/secure', '/var/log/auth.log']
            for log_dir in log_dirs:
                if self.check_file_exists(target, log_dir):
                    cmd = f"grep -i 'sshd.*session opened' {log_dir} | wc -l"
                    result = self.execute_command(target, cmd)

                    if result['exit_code'] == 0 and int(result['stdout'].strip()) > 0:
                        monitoring['access_logging'] = True
                        monitoring['details'].append(f"Log di accesso SSH trovati in {log_dir}")
                        monitoring['implemented'] = True

        elif target.os_type.lower() == 'windows':
            # Verifica audit policy per login/logout remoto
            cmd = 'powershell -Command "auditpol /get /subcategory:\'Logon\',\'Logoff\',\'Special Logon\' | Select-String \'Success\'"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and len(result['stdout'].strip().split('\n')) >= 2:
                monitoring['access_logging'] = True
                monitoring['details'].append("Audit policy configurata per eventi di login/logout")
                monitoring['implemented'] = True

            # Verifica logging RDP
            cmd = 'powershell -Command "Get-WinEvent -LogName \'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational\' -MaxEvents 1 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                monitoring['session_logging'] = True
                monitoring['details'].append("Logging delle sessioni RDP attivo")
                monitoring['implemented'] = True

            # Verifica Windows Event Forwarding
            cmd = 'powershell -Command "Get-WinEvent -LogName \'ForwardedEvents\' -MaxEvents 1 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
            result = self.execute_command(target, cmd)

            if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                monitoring['alert_system'] = True
                monitoring['details'].append("Windows Event Forwarding configurato")
                monitoring['implemented'] = True

            # Verifica software di monitoraggio
            monitoring_software = ['SIEM', 'Splunk', 'LogRhythm', 'ArcSight', 'QRadar', 'EventLog Analyzer']
            for software in monitoring_software:
                cmd = f'powershell -Command "Get-ItemProperty HKLM:\\Software\\*\\*, HKLM:\\Software\\Wow6432Node\\*\\* | Where-Object {{ $_.DisplayName -match \'{software}\' }} | Measure-Object | Select-Object -ExpandProperty Count"'
                result = self.execute_command(target, cmd)

                if result['exit_code'] == 0 and result['stdout'].strip() != '0':
                    monitoring['alert_system'] = True
                    monitoring['details'].append(f"Software di monitoraggio trovato: {software}")
                    monitoring['implemented'] = True

        return monitoring

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