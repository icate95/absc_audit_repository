"""
Authentication Provider - Interfaccia base per i provider di autenticazione.

Questo modulo definisce l'interfaccia comune che tutti i provider di
autenticazione devono implementare.
"""

from abc import ABC, abstractmethod
from typing import Optional, Tuple

from absc_audit.storage.models import UserAccount
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class AuthenticationProvider(ABC):
    """
    Interfaccia base per i provider di autenticazione.

    Definisce i metodi che tutti i provider di autenticazione devono implementare.
    Questo permette di avere una gestione uniforme dell'autenticazione
    indipendentemente dal meccanismo utilizzato.
    """

    @abstractmethod
    def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[UserAccount]]:
        """
        Autentica un utente.

        Args:
            username: Nome utente
            password: Password

        Returns:
            Tuple with (success, user_account)
        """
        pass

    @abstractmethod
    def get_user_by_username(self, username: str) -> Optional[UserAccount]:
        """
        Ottiene un utente dal suo username.

        Args:
            username: Nome utente

        Returns:
            Account dell'utente o None se non trovato
        """
        pass

    @abstractmethod
    def verify_password(self, username: str, password: str) -> bool:
        """
        Verifica se la password di un utente è corretta.

        Args:
            username: Nome utente
            password: Password da verificare

        Returns:
            True se la password è corretta, False altrimenti
        """
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """
        Restituisce il nome del provider.

        Returns:
            Nome del provider
        """
        pass