"""
LDAP Configuration - Utilità per la configurazione LDAP.

Questo modulo fornisce funzioni e classi per configurare facilmente
l'autenticazione LDAP per diversi ambienti.
"""

from typing import Dict, List, Optional, Any

from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class LDAPConfigBuilder:
    """
    Builder per configurazioni LDAP.

    Questa classe semplifica la creazione di configurazioni LDAP
    per diversi ambienti e directory server.
    """

    def __init__(self, server_uri: str = "ldap://localhost:389"):
        """
        Inizializza il builder.

        Args:
            server_uri: URI del server LDAP
        """
        self.config = {
            'server_uri': server_uri,
            'base_dn': "",
            'use_tls': False
        }

    def with_base_dn(self, base_dn: str) -> 'LDAPConfigBuilder':
        """
        Imposta il DN base.

        Args:
            base_dn: DN base

        Returns:
            Self per method chaining
        """
        self.config['base_dn'] = base_dn
        return self

    def with_user_search(self,
                         user_search_base: Optional[str] = None,
                         user_search_filter: str = "(sAMAccountName={username})",
                         user_dn_template: Optional[str] = None) -> 'LDAPConfigBuilder':
        """
        Configura la ricerca utenti.

        Args:
            user_search_base: Base per la ricerca utenti (opzionale, default=base_dn)
            user_search_filter: Filtro di ricerca utenti
            user_dn_template: Template per il DN utente (opzionale)

        Returns:
            Self per method chaining
        """
        if user_search_base:
            self.config['user_search_base'] = user_search_base

        self.config['user_search_filter'] = user_search_filter

        if user_dn_template:
            self.config['user_dn_template'] = user_dn_template

        return self

    def with_group_search(self,
                          group_search_base: Optional[str] = None,
                          group_search_filter: str = "(member={user_dn})") -> 'LDAPConfigBuilder':
        """
        Configura la ricerca gruppi.

        Args:
            group_search_base: Base per la ricerca gruppi (opzionale, default=base_dn)
            group_search_filter: Filtro di ricerca gruppi

        Returns:
            Self per method chaining
        """
        if group_search_base:
            self.config['group_search_base'] = group_search_base

        self.config['group_search_filter'] = group_search_filter

        return self

    def with_admin_group(self, admin_group: str) -> 'LDAPConfigBuilder':
        """
        Imposta il gruppo degli amministratori.

        Args:
            admin_group: DN del gruppo degli amministratori

        Returns:
            Self per method chaining
        """
        self.config['admin_group'] = admin_group
        return self

    def with_user_group(self, user_group: str) -> 'LDAPConfigBuilder':
        """
        Imposta il gruppo degli utenti.

        Args:
            user_group: DN del gruppo degli utenti

        Returns:
            Self per method chaining
        """
        self.config['user_group'] = user_group
        return self

    def with_bind_credentials(self, bind_dn: str, bind_password: str) -> 'LDAPConfigBuilder':
        """
        Imposta le credenziali per il bind iniziale.

        Args:
            bind_dn: DN per il bind iniziale
            bind_password: Password per il bind iniziale

        Returns:
            Self per method chaining
        """
        self.config['bind_dn'] = bind_dn
        self.config['bind_password'] = bind_password
        return self

    def with_tls(self,
                 use_tls: bool = True,
                 cert_file: Optional[str] = None,
                 ca_cert_file: Optional[str] = None) -> 'LDAPConfigBuilder':
        """
        Configura TLS.

        Args:
            use_tls: Usa TLS
            cert_file: File certificato client (opzionale)
            ca_cert_file: File certificato CA (opzionale)

        Returns:
            Self per method chaining
        """
        self.config['use_tls'] = use_tls

        if cert_file:
            self.config['cert_file'] = cert_file

        if ca_cert_file:
            self.config['ca_cert_file'] = ca_cert_file

        return self

    def with_attribute_mapping(self, attr_mapping: Dict[str, str]) -> 'LDAPConfigBuilder':
        """
        Imposta la mappatura degli attributi.

        Args:
            attr_mapping: Mappatura degli attributi

        Returns:
            Self per method chaining
        """
        self.config['attr_mapping'] = attr_mapping
        return self

    def build(self) -> Dict[str, Any]:
        """
        Costruisce la configurazione LDAP.

        Returns:
            Configurazione LDAP
        """
        # Verifica che i campi obbligatori siano definiti
        if not self.config['base_dn']:
            logger.warning("base_dn not defined in LDAP configuration")

        # Imposta i valori di default
        if 'user_search_base' not in self.config:
            self.config['user_search_base'] = self.config['base_dn']

        if 'group_search_base' not in self.config:
            self.config['group_search_base'] = self.config['base_dn']

        if 'user_dn_template' not in self.config:
            self.config['user_dn_template'] = f"cn={{username}},{self.config['base_dn']}"

        if 'admin_group' not in self.config:
            self.config['admin_group'] = f"CN=Administrators,{self.config['base_dn']}"

        if 'user_group' not in self.config:
            self.config['user_group'] = f"CN=Users,{self.config['base_dn']}"

        if 'attr_mapping' not in self.config:
            self.config['attr_mapping'] = {
                'username': 'sAMAccountName',
                'email': 'mail',
                'first_name': 'givenName',
                'last_name': 'sn',
                'display_name': 'displayName'
            }

        return self.config


# ----- Funzioni di utility e configurazioni predefinite -----

def create_active_directory_config(server_uri: str,
                                   domain: str,
                                   bind_user: str,
                                   bind_password: str,
                                   use_tls: bool = True) -> Dict[str, Any]:
    """
    Crea una configurazione per Active Directory.

    Args:
        server_uri: URI del server AD
        domain: Dominio AD (es. "example.com")
        bind_user: Utente per il bind (es. "admin")
        bind_password: Password per il bind
        use_tls: Usa TLS

    Returns:
        Configurazione LDAP per Active Directory
    """
    # Converti il dominio in DN base
    domain_parts = domain.split('.')
    base_dn = ','.join([f"DC={part}" for part in domain_parts])

    # Crea la configurazione
    builder = LDAPConfigBuilder(server_uri)

    return builder.with_base_dn(base_dn) \
        .with_user_search(user_search_filter="(&(objectClass=user)(sAMAccountName={username}))") \
        .with_group_search(group_search_filter="(&(objectClass=group)(member={user_dn}))") \
        .with_admin_group(f"CN=Domain Admins,CN=Users,{base_dn}") \
        .with_user_group(f"CN=Domain Users,CN=Users,{base_dn}") \
        .with_bind_credentials(f"{bind_user}@{domain}", bind_password) \
        .with_tls(use_tls) \
        .build()


def create_openldap_config(server_uri: str,
                           base_dn: str,
                           bind_dn: str,
                           bind_password: str,
                           use_tls: bool = True) -> Dict[str, Any]:
    """
    Crea una configurazione per OpenLDAP.

    Args:
        server_uri: URI del server OpenLDAP
        base_dn: DN base (es. "dc=example,dc=com")
        bind_dn: DN per il bind (es. "cn=admin,dc=example,dc=com")
        bind_password: Password per il bind
        use_tls: Usa TLS

    Returns:
        Configurazione LDAP per OpenLDAP
    """
    # Crea la configurazione
    builder = LDAPConfigBuilder(server_uri)

    return builder.with_base_dn(base_dn) \
        .with_user_search(user_search_filter="(&(objectClass=inetOrgPerson)(uid={username}))") \
        .with_group_search(group_search_filter="(&(objectClass=groupOfNames)(member={user_dn}))") \
        .with_admin_group(f"cn=admins,{base_dn}") \
        .with_user_group(f"cn=users,{base_dn}") \
        .with_bind_credentials(bind_dn, bind_password) \
        .with_tls(use_tls) \
        .with_attribute_mapping({
        'username': 'uid',
        'email': 'mail',
        'first_name': 'givenName',
        'last_name': 'sn',
        'display_name': 'cn'
    }) \
        .build()


def create_freeipa_config(server_uri: str,
                          domain: str,
                          bind_user: str,
                          bind_password: str,
                          use_tls: bool = True) -> Dict[str, Any]:
    """
    Crea una configurazione per FreeIPA.

    Args:
        server_uri: URI del server FreeIPA
        domain: Dominio FreeIPA (es. "example.com")
        bind_user: Utente per il bind (es. "admin")
        bind_password: Password per il bind
        use_tls: Usa TLS

    Returns:
        Configurazione LDAP per FreeIPA
    """
    # Converti il dominio in DN base
    domain_parts = domain.split('.')
    base_dn = ','.join([f"dc={part}" for part in domain_parts])

    # Crea la configurazione
    builder = LDAPConfigBuilder(server_uri)

    return builder.with_base_dn(base_dn) \
        .with_user_search(user_search_base=f"cn=users,cn=accounts,{base_dn}",
                          user_search_filter="(&(objectClass=inetOrgPerson)(uid={username}))") \
        .with_group_search(group_search_base=f"cn=groups,cn=accounts,{base_dn}",
                           group_search_filter="(&(objectClass=groupOfNames)(member={user_dn}))") \
        .with_admin_group(f"cn=admins,cn=groups,cn=accounts,{base_dn}") \
        .with_user_group(f"cn=users,cn=groups,cn=accounts,{base_dn}") \
        .with_bind_credentials(f"uid={bind_user},cn=users,cn=accounts,{base_dn}", bind_password) \
        .with_tls(use_tls) \
        .with_attribute_mapping({
        'username': 'uid',
        'email': 'mail',
        'first_name': 'givenName',
        'last_name': 'sn',
        'display_name': 'cn'
    }) \
        .build()