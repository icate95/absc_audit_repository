"""
LDAP Authentication Provider - Provider di autenticazione LDAP/Active Directory.

Questo modulo implementa un provider di autenticazione che utilizza LDAP o
Active Directory per autenticare gli utenti.
"""

import uuid
from typing import Dict, List, Optional, Any, Tuple

from absc_audit.auth.authentication_provider import AuthenticationProvider
from absc_audit.auth.ldap_auth import LDAPAuthenticator
from absc_audit.storage.models import UserAccount
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class LDAPAuthenticationProvider(AuthenticationProvider):
    """
    Provider di autenticazione che utilizza LDAP o Active Directory.

    Questa classe implementa l'interfaccia AuthenticationProvider utilizzando
    l'autenticazione LDAP/AD tramite la classe LDAPAuthenticator.
    """

    def __init__(self, ldap_config: Dict[str, Any], storage_backend=None):
        """
        Inizializza il provider di autenticazione LDAP.

        Args:
            ldap_config: Configurazione LDAP
            storage_backend: Storage backend per la sincronizzazione utenti (opzionale)
        """
        self.ldap_authenticator = LDAPAuthenticator(ldap_config)
        self.storage_backend = storage_backend
        self._provider_name = 'ldap'

    def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[UserAccount]]:
        """
        Autentica un utente tramite LDAP.

        Args:
            username: Nome utente
            password: Password

        Returns:
            Tuple with (success, user_account)
        """
        logger.debug(f"Authenticating user {username} with LDAP")

        # Tenta l'autenticazione LDAP
        success, user_data = self.ldap_authenticator.authenticate(username, password)

        if not success:
            logger.warning(f"LDAP authentication failed for user {username}")
            return False, None

        # Crea o aggiorna l'account utente
        user_account = self._create_or_update_user(user_data)

        return True, user_account

    def get_user_by_username(self, username: str) -> Optional[UserAccount]:
        """
        Ottiene un utente dal suo username tramite LDAP.

        Args:
            username: Nome utente

        Returns:
            Account dell'utente o None se non trovato
        """
        logger.debug(f"Getting user {username} from LDAP")

        # Cerca l'utente in LDAP
        user_data = self.ldap_authenticator.get_user_by_username(username)

        if not user_data:
            logger.warning(f"User {username} not found in LDAP")
            return None

        # Crea o aggiorna l'account utente
        user_account = self._create_or_update_user(user_data)

        return user_account

    def verify_password(self, username: str, password: str) -> bool:
        """
        Verifica se la password di un utente è corretta tramite LDAP.

        Args:
            username: Nome utente
            password: Password da verificare

        Returns:
            True se la password è corretta, False altrimenti
        """
        return self.ldap_authenticator.verify_password(username, password)

    @property
    def provider_name(self) -> str:
        """
        Restituisce il nome del provider.

        Returns:
            Nome del provider
        """
        return self._provider_name

    def _create_or_update_user(self, user_data: Dict[str, Any]) -> UserAccount:
        """
        Crea o aggiorna un account utente basato sui dati LDAP.

        Args:
            user_data: Dati dell'utente da LDAP

        Returns:
            Account utente
        """
        username = user_data.get('username', '')
        existing_user = None

        # Se abbiamo uno storage backend, verifica se l'utente esiste già
        if self.storage_backend:
            try:
                from absc_audit.auth.local_auth import LocalAuthenticationProvider
                local_provider = LocalAuthenticationProvider(self.storage_backend)
                existing_user = local_provider.get_user_by_username(username)
            except Exception as e:
                logger.error(f"Error getting user from storage: {str(e)}")

        if existing_user:
            # Aggiorna l'utente esistente con i dati LDAP
            existing_user.email = user_data.get('email', existing_user.email)
            existing_user.first_name = user_data.get('first_name', existing_user.first_name)
            existing_user.last_name = user_data.get('last_name', existing_user.last_name)
            existing_user.role = user_data.get('role', existing_user.role)

            # Salva l'utente aggiornato
            if self.storage_backend:
                try:
                    self.storage_backend.save_user(existing_user)
                except Exception as e:
                    logger.error(f"Error saving updated user: {str(e)}")

            return existing_user
        else:
            # Crea un nuovo account utente
            user = UserAccount(
                id=str(uuid.uuid4()),
                username=username,
                password_hash="LDAP_AUTH",  # Password non necessaria per auth LDAP
                email=user_data.get('email', ''),
                first_name=user_data.get('first_name', ''),
                last_name=user_data.get('last_name', ''),
                role=user_data.get('role', 'user')
            )

            # Salva il nuovo utente
            if self.storage_backend:
                try:
                    self.storage_backend.save_user(user)
                except Exception as e:
                    logger.error(f"Error saving new user: {str(e)}")

            return user