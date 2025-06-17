"""
LDAP Authentication - Implementazione dell'autenticazione tramite LDAP/Active Directory.

Questo modulo implementa le funzionalità di autenticazione tramite
protocollo LDAP, consentendo l'integrazione con Active Directory o
altre directory LDAP.
"""

import os
import logging
from typing import Dict, List, Optional, Any, Tuple, Union

# Importazioni condizionali per gestire le dipendenze
try:
    import ldap
    from ldap.filter import escape_filter_chars

    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False

from absc_audit.utils.logging import setup_logger
from absc_audit.storage.models import UserAccount

logger = setup_logger(__name__)


class LDAPAuthenticator:
    """
    Classe per l'autenticazione tramite LDAP/Active Directory.

    Questa classe gestisce l'autenticazione degli utenti tramite LDAP,
    consentendo l'integrazione con Active Directory o altre directory LDAP.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Inizializza il sistema di autenticazione LDAP.

        Args:
            config: Configurazione LDAP (server, base DN, filtri, ecc.)
        """
        if not HAS_LDAP:
            logger.error("Modulo python-ldap non installato. L'autenticazione LDAP non funzionerà.")
            raise ImportError("Modulo python-ldap non installato. Installare con 'pip install python-ldap'")

        # Configurazione LDAP
        self.server_uri = config.get('server_uri', 'ldap://localhost:389')
        self.base_dn = config.get('base_dn', '')
        self.user_dn_template = config.get('user_dn_template', 'cn={username},' + self.base_dn)
        self.user_search_base = config.get('user_search_base', self.base_dn)
        self.user_search_filter = config.get('user_search_filter', '(sAMAccountName={username})')
        self.group_search_base = config.get('group_search_base', self.base_dn)
        self.group_search_filter = config.get('group_search_filter', '(member={user_dn})')
        self.admin_group = config.get('admin_group', 'CN=Administrators,' + self.base_dn)
        self.user_group = config.get('user_group', 'CN=Users,' + self.base_dn)
        self.bind_dn = config.get('bind_dn', '')  # DN per bind iniziale, se necessario
        self.bind_password = config.get('bind_password', '')
        self.use_tls = config.get('use_tls', False)
        self.cert_file = config.get('cert_file', '')
        self.ca_cert_file = config.get('ca_cert_file', '')

        # Mappatura attributi LDAP -> attributi utente
        self.attr_mapping = config.get('attr_mapping', {
            'username': 'sAMAccountName',
            'email': 'mail',
            'first_name': 'givenName',
            'last_name': 'sn',
            'display_name': 'displayName'
        })

        # Opzioni LDAP
        ldap.set_option(ldap.OPT_REFERRALS, 0)
        if self.use_tls:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            if self.ca_cert_file:
                ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, self.ca_cert_file)
            if self.cert_file:
                ldap.set_option(ldap.OPT_X_TLS_CERTFILE, self.cert_file)

        # Cache delle connessioni
        self.conn = None

    def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Autentica un utente tramite LDAP.

        Args:
            username: Nome utente
            password: Password

        Returns:
            Tupla con stato autenticazione (bool) e dati utente (Dict o None)
        """
        if not HAS_LDAP:
            logger.error("Modulo python-ldap non installato. Impossibile autenticare.")
            return False, None

        try:
            # Inizializza connessione LDAP
            self.conn = ldap.initialize(self.server_uri)

            # Abilita TLS se configurato
            if self.use_tls:
                self.conn.start_tls_s()

            # Se richiesto, esegui prima un bind con credenziali di servizio
            if self.bind_dn and self.bind_password:
                self.conn.simple_bind_s(self.bind_dn, self.bind_password)

                # Cerca l'utente
                user_filter = self.user_search_filter.format(username=escape_filter_chars(username))
                logger.debug(f"Searching user with filter: {user_filter}")

                result = self.conn.search_s(
                    self.user_search_base,
                    ldap.SCOPE_SUBTREE,
                    user_filter,
                    ['*']
                )

                if not result:
                    logger.warning(f"User {username} not found in LDAP")
                    return False, None

                user_dn = result[0][0]
                user_attrs = result[0][1]

                # Reinizializza la connessione per l'autenticazione dell'utente
                self.conn.unbind_s()
                self.conn = ldap.initialize(self.server_uri)
                if self.use_tls:
                    self.conn.start_tls_s()
            else:
                # Binding diretto con le credenziali dell'utente
                user_dn = self.user_dn_template.format(username=escape_filter_chars(username))
                user_attrs = None

            # Autentica l'utente
            logger.debug(f"Authenticating user with DN: {user_dn}")
            self.conn.simple_bind_s(user_dn, password)

            # Se siamo qui, l'autenticazione è riuscita

            # Se non abbiamo già gli attributi, li recuperiamo
            if user_attrs is None:
                result = self.conn.search_s(
                    user_dn,
                    ldap.SCOPE_BASE,
                    '(objectClass=*)',
                    ['*']
                )
                user_attrs = result[0][1]

            # Controlla l'appartenenza ai gruppi
            user_groups = self._get_user_groups(user_dn)

            # Determina il ruolo dell'utente
            role = "viewer"  # Default role
            if self.admin_group in user_groups:
                role = "admin"
            elif self.user_group in user_groups:
                role = "user"

            # Mappa gli attributi LDAP agli attributi dell'utente
            user_data = self._map_user_attributes(user_attrs)
            user_data['role'] = role
            user_data['username'] = username

            logger.info(f"User {username} authenticated successfully via LDAP")
            return True, user_data

        except ldap.INVALID_CREDENTIALS:
            logger.warning(f"Invalid credentials for user {username}")
            return False, None
        except ldap.SERVER_DOWN:
            logger.error(f"LDAP server is down or unavailable: {self.server_uri}")
            return False, None
        except ldap.LDAPError as e:
            logger.error(f"LDAP error during authentication: {str(e)}")
            return False, None
        finally:
            if self.conn:
                self.conn.unbind_s()
                self.conn = None

    def _get_user_groups(self, user_dn: str) -> List[str]:
        """
        Ottiene i gruppi di cui l'utente è membro.

        Args:
            user_dn: DN dell'utente

        Returns:
            Lista di DN dei gruppi
        """
        try:
            group_filter = self.group_search_filter.format(user_dn=escape_filter_chars(user_dn))
            logger.debug(f"Searching groups with filter: {group_filter}")

            result = self.conn.search_s(
                self.group_search_base,
                ldap.SCOPE_SUBTREE,
                group_filter,
                ['cn']
            )

            return [entry[0] for entry in result]
        except ldap.LDAPError as e:
            logger.error(f"Error getting user groups: {str(e)}")
            return []

    def _map_user_attributes(self, ldap_attrs: Dict[str, List[bytes]]) -> Dict[str, str]:
        """
        Mappa gli attributi LDAP agli attributi dell'utente.

        Args:
            ldap_attrs: Attributi LDAP

        Returns:
            Dizionario con attributi mappati
        """
        user_data = {}

        for user_attr, ldap_attr in self.attr_mapping.items():
            if ldap_attr in ldap_attrs and ldap_attrs[ldap_attr]:
                # LDAP restituisce valori come liste di byte
                attr_value = ldap_attrs[ldap_attr][0]
                # Converti in stringa se necessario
                if isinstance(attr_value, bytes):
                    attr_value = attr_value.decode('utf-8')
                user_data[user_attr] = attr_value
            else:
                user_data[user_attr] = ""

        return user_data

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Ottiene i dati di un utente tramite nome utente.

        Args:
            username: Nome utente

        Returns:
            Dizionario con dati utente o None se non trovato
        """
        if not HAS_LDAP:
            logger.error("Modulo python-ldap non installato. Impossibile cercare l'utente.")
            return None

        try:
            # Inizializza connessione LDAP
            self.conn = ldap.initialize(self.server_uri)

            # Abilita TLS se configurato
            if self.use_tls:
                self.conn.start_tls_s()

            # Binding con credenziali di servizio
            if self.bind_dn and self.bind_password:
                self.conn.simple_bind_s(self.bind_dn, self.bind_password)
            else:
                logger.error("Bind DN e password non configurati. Impossibile cercare l'utente.")
                return None

            # Cerca l'utente
            user_filter = self.user_search_filter.format(username=escape_filter_chars(username))
            logger.debug(f"Searching user with filter: {user_filter}")

            result = self.conn.search_s(
                self.user_search_base,
                ldap.SCOPE_SUBTREE,
                user_filter,
                ['*']
            )

            if not result:
                logger.warning(f"User {username} not found in LDAP")
                return None

            user_dn = result[0][0]
            user_attrs = result[0][1]

            # Controlla l'appartenenza ai gruppi
            user_groups = self._get_user_groups(user_dn)

            # Determina il ruolo dell'utente
            role = "viewer"  # Default role
            if self.admin_group in user_groups:
                role = "admin"
            elif self.user_group in user_groups:
                role = "user"

            # Mappa gli attributi LDAP agli attributi dell'utente
            user_data = self._map_user_attributes(user_attrs)
            user_data['role'] = role
            user_data['username'] = username

            return user_data

        except ldap.LDAPError as e:
            logger.error(f"LDAP error during user search: {str(e)}")
            return None
        finally:
            if self.conn:
                self.conn.unbind_s()
                self.conn = None

    def verify_password(self, username: str, password: str) -> bool:
        """
        Verifica la password di un utente.

        Args:
            username: Nome utente
            password: Password da verificare

        Returns:
            True se la password è corretta, False altrimenti
        """
        authenticated, _ = self.authenticate(username, password)
        return authenticated