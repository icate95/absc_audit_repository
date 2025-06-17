"""
Authentication Service - Servizio che gestisce l'autenticazione utenti.

Questo modulo implementa un servizio che coordina diversi provider di
autenticazione per autenticare gli utenti.
"""

from typing import Dict, List, Optional, Any, Tuple

from absc_audit.auth.authentication_provider import AuthenticationProvider
from absc_audit.storage.models import UserAccount
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class AuthenticationService:
    """
    Servizio che gestisce l'autenticazione degli utenti.

    Questa classe coordina diversi provider di autenticazione e implementa
    la logica per decidere quale provider utilizzare e in che ordine.
    """

    def __init__(self):
        """Inizializza il servizio di autenticazione."""
        self.providers = {}
        self.provider_order = []

    def register_provider(self, provider: AuthenticationProvider, priority: int = 0):
        """
        Registra un provider di autenticazione.

        Args:
            provider: Provider di autenticazione
            priority: Priorità del provider (più alto = maggiore priorità)
        """
        provider_name = provider.provider_name
        logger.info(f"Registering authentication provider: {provider_name} with priority {priority}")

        self.providers[provider_name] = {
            'provider': provider,
            'priority': priority
        }

        # Aggiorna l'ordine dei provider
        self._update_provider_order()

    def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[UserAccount], Optional[str]]:
        """
        Autentica un utente utilizzando i provider registrati.

        Args:
            username: Nome utente
            password: Password

        Returns:
            Tuple with (success, user_account, provider_name)
        """
        logger.debug(f"Authenticating user {username}")

        # Tenta l'autenticazione con ciascun provider nell'ordine di priorità
        for provider_name in self.provider_order:
            provider = self.providers[provider_name]['provider']

            logger.debug(f"Trying authentication with provider: {provider_name}")
            success, user = provider.authenticate(username, password)

            if success:
                logger.info(f"User {username} authenticated successfully with provider: {provider_name}")
                return True, user, provider_name

        logger.warning(f"Authentication failed for user {username} with all providers")
        return False, None, None

    def get_user_by_username(self, username: str) -> Tuple[Optional[UserAccount], Optional[str]]:
        """
        Ottiene un utente dal suo username utilizzando i provider registrati.

        Args:
            username: Nome utente

        Returns:
            Tuple with (user_account, provider_name)
        """
        logger.debug(f"Getting user {username}")

        # Cerca l'utente con ciascun provider nell'ordine di priorità
        for provider_name in self.provider_order:
            provider = self.providers[provider_name]['provider']

            logger.debug(f"Trying to get user with provider: {provider_name}")
            user = provider.get_user_by_username(username)

            if user:
                logger.debug(f"User {username} found with provider: {provider_name}")
                return user, provider_name

        logger.warning(f"User {username} not found with any provider")
        return None, None

    def verify_password(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """
        Verifica se la password di un utente è corretta utilizzando i provider registrati.

        Args:
            username: Nome utente
            password: Password da verificare

        Returns:
            Tuple with (is_valid, provider_name)
        """
        logger.debug(f"Verifying password for user {username}")

        # Verifica la password con ciascun provider nell'ordine di priorità
        for provider_name in self.provider_order:
            provider = self.providers[provider_name]['provider']

            logger.debug(f"Trying to verify password with provider: {provider_name}")
            is_valid = provider.verify_password(username, password)

            if is_valid:
                logger.debug(f"Password for user {username} verified with provider: {provider_name}")
                return True, provider_name

        logger.warning(f"Password verification failed for user {username} with all providers")
        return False, None

    def _update_provider_order(self):
        """Aggiorna l'ordine dei provider in base alla priorità."""
        self.provider_order = sorted(
            self.providers.keys(),
            key=lambda x: self.providers[x]['priority'],
            reverse=True  # Priorità più alta prima
        )

        logger.debug(f"Updated provider order: {self.provider_order}")