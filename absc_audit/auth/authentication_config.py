"""
Authentication Configuration - Configurazione del sistema di autenticazione.

Questo modulo fornisce funzioni e classi per configurare facilmente
il sistema di autenticazione nell'applicazione.
"""

from typing import Dict, List, Optional, Any

from absc_audit.auth.authentication_service import AuthenticationService
from absc_audit.auth.authentication_middleware import AuthenticationMiddleware
from absc_audit.auth.local_authentication_provider import LocalAuthenticationProvider
from absc_audit.auth.ldap_authentication_provider import LDAPAuthenticationProvider
from absc_audit.config.settings import Settings
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class AuthenticationConfig:
    """
    Configurazione del sistema di autenticazione.

    Questa classe semplifica la configurazione del sistema di autenticazione
    nell'applicazione, supportando diversi provider e middleware.
    """

    def __init__(self, storage_backend=None, settings: Optional[Settings] = None):
        """
        Inizializza la configurazione di autenticazione.

        Args:
            storage_backend: Storage backend per l'accesso ai dati utente
            settings: Configurazioni del sistema (opzionale)
        """
        self.settings = settings or Settings()
        self.storage_backend = storage_backend
        self.auth_service = AuthenticationService()
        self.providers = {}

        logger.info("Initializing authentication configuration")

    def configure_local_auth(self, priority: int = 10) -> 'AuthenticationConfig':
        """
        Configura l'autenticazione locale.

        Args:
            priority: Priorità del provider (più alto = maggiore priorità)

        Returns:
            Self per method chaining
        """
        if not self.storage_backend:
            logger.warning("Storage backend not configured, cannot set up local authentication")
            return self

        logger.info("Configuring local authentication")

        # Crea il provider di autenticazione locale
        local_provider = LocalAuthenticationProvider(self.storage_backend)

        # Registra il provider nel servizio di autenticazione
        self.auth_service.register_provider(local_provider, priority)

        # Memorizza il provider
        self.providers['local'] = local_provider

        return self

    def configure_ldap_auth(self, ldap_config: Dict[str, Any], priority: int = 20) -> 'AuthenticationConfig':
        """
        Configura l'autenticazione LDAP/AD.

        Args:
            ldap_config: Configurazione LDAP
            priority: Priorità del provider (più alto = maggiore priorità)

        Returns:
            Self per method chaining
        """
        logger.info("Configuring LDAP authentication")

        try:
            # Crea il provider di autenticazione LDAP
            ldap_provider = LDAPAuthenticationProvider(ldap_config, self.storage_backend)

            # Registra il provider nel servizio di autenticazione
            self.auth_service.register_provider(ldap_provider, priority)

            # Memorizza il provider
            self.providers['ldap'] = ldap_provider

        except Exception as e:
            logger.error(f"Error configuring LDAP authentication: {str(e)}")

        return self

    def build_middleware(self) -> AuthenticationMiddleware:
        """
        Crea il middleware di autenticazione.

        Returns:
            Middleware di autenticazione configurato
        """
        logger.info("Building authentication middleware")

        return AuthenticationMiddleware(self.auth_service)

    def create_admin_user(self, username: str, password: str, email: str = "",
                          first_name: str = "", last_name: str = "") -> bool:
        """
        Crea un utente amministratore locale.

        Args:
            username: Nome utente
            password: Password
            email: Email (opzionale)
            first_name: Nome (opzionale)
            last_name: Cognome (opzionale)

        Returns:
            True se l'utente è stato creato, False altrimenti
        """
        if 'local' not in self.providers:
            logger.error("Local authentication provider not configured, cannot create admin user")
            return False

        logger.info(f"Creating admin user {username}")

        try:
            # Utilizza il provider locale per creare l'utente
            local_provider = self.providers['local']
            local_provider.create_user(
                username=username,
                password=password,
                email=email,
                first_name=first_name,
                last_name=last_name,
                role="admin"
            )

            return True

        except Exception as e:
            logger.error(f"Error creating admin user: {str(e)}")
            return False


# ----- Funzioni di utility -----

def configure_authentication(storage_backend=None,
                             settings: Optional[Settings] = None,
                             enable_local: bool = True,
                             enable_ldap: bool = False,
                             ldap_config: Optional[Dict[str, Any]] = None) -> AuthenticationMiddleware:
    """
    Configura il sistema di autenticazione e restituisce il middleware.

    Args:
        storage_backend: Storage backend per l'accesso ai dati utente
        settings: Configurazioni del sistema (opzionale)
        enable_local: Abilita l'autenticazione locale
        enable_ldap: Abilita l'autenticazione LDAP/AD
        ldap_config: Configurazione LDAP (necessaria se enable_ldap=True)

    Returns:
        Middleware di autenticazione configurato
    """
    auth_config = AuthenticationConfig(storage_backend, settings)

    if enable_local:
        auth_config.configure_local_auth()

    if enable_ldap:
        if not ldap_config:
            logger.warning("LDAP authentication enabled but no configuration provided")
        else:
            auth_config.configure_ldap_auth(ldap_config)

    return auth_config.build_middleware()