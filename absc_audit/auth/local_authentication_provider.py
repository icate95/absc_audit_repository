"""
Local Authentication Provider - Provider di autenticazione locale.

Questo modulo implementa un provider di autenticazione che utilizza il
database locale per autenticare gli utenti.
"""

import hashlib
import datetime
from typing import Dict, List, Optional, Any, Tuple

from absc_audit.auth.authentication_provider import AuthenticationProvider
from absc_audit.storage.models import UserAccount
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class LocalAuthenticationProvider(AuthenticationProvider):
    """
    Provider di autenticazione che utilizza il database locale.

    Questa classe implementa l'interfaccia AuthenticationProvider utilizzando
    il database locale per autenticare gli utenti.
    """

    def __init__(self, storage_backend):
        """
        Inizializza il provider di autenticazione locale.

        Args:
            storage_backend: Storage backend per l'accesso ai dati utente
        """
        self.storage_backend = storage_backend
        self._provider_name = 'local'

    def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[UserAccount]]:
        """
        Autentica un utente utilizzando il database locale.

        Args:
            username: Nome utente
            password: Password

        Returns:
            Tuple with (success, user_account)
        """
        logger.debug(f"Authenticating user {username} locally")

        # Ottieni l'utente dal database
        user = self.get_user_by_username(username)

        if not user:
            logger.warning(f"User {username} not found in local database")
            return False, None

        # Verifica se l'utente è abilitato
        if not user.enabled:
            logger.warning(f"User {username} is disabled")
            return False, None

        # Verifica la password
        if not self.verify_password(username, password):
            logger.warning(f"Invalid password for user {username}")
            return False, None

        # Aggiorna l'ultimo accesso
        user.last_login = datetime.datetime.now()
        try:
            self.storage_backend.save_user(user)
        except Exception as e:
            logger.error(f"Error updating last login for user {username}: {str(e)}")

        return True, user

    def get_user_by_username(self, username: str) -> Optional[UserAccount]:
        """
        Ottiene un utente dal suo username utilizzando il database locale.

        Args:
            username: Nome utente

        Returns:
            Account dell'utente o None se non trovato
        """
        logger.debug(f"Getting user {username} from local database")

        try:
            # Ottieni tutti gli utenti (in un'implementazione reale si utilizzerebbe una query più efficiente)
            users = self.storage_backend.get_all_users()

            # Cerca l'utente per username
            for user in users:
                if user.username == username:
                    return user

            logger.warning(f"User {username} not found in local database")
            return None
        except Exception as e:
            logger.error(f"Error getting user {username} from local database: {str(e)}")
            return None

    def verify_password(self, username: str, password: str) -> bool:
        """
        Verifica se la password di un utente è corretta utilizzando il database locale.

        Args:
            username: Nome utente
            password: Password da verificare

        Returns:
            True se la password è corretta, False altrimenti
        """
        logger.debug(f"Verifying password for user {username}")

        # Ottieni l'utente
        user = self.get_user_by_username(username)

        if not user:
            logger.warning(f"User {username} not found in local database")
            return False

        # Se l'utente è autenticato tramite LDAP, non abbiamo una password locale
        if user.password_hash == "LDAP_AUTH":
            logger.warning(f"User {username} is authenticated via LDAP, cannot verify password locally")
            return False

        # Verifica la password
        hashed_password = self._hash_password(password)

        # In un'implementazione reale, si utilizzerebbero algoritmi più sicuri come bcrypt o PBKDF2
        return user.password_hash == hashed_password

    @property
    def provider_name(self) -> str:
        """
        Restituisce il nome del provider.

        Returns:
            Nome del provider
        """
        return self._provider_name

    def create_user(self, username: str, password: str, email: str = "",
                    first_name: str = "", last_name: str = "",
                    role: str = "user") -> UserAccount:
        """
        Crea un nuovo utente nel database locale.

        Args:
            username: Nome utente
            password: Password
            email: Email (opzionale)
            first_name: Nome (opzionale)
            last_name: Cognome (opzionale)
            role: Ruolo (opzionale, default "user")

        Returns:
            Account utente creato

        Raises:
            ValueError: Se l'utente esiste già
        """
        logger.debug(f"Creating user {username}")

        # Verifica se l'utente esiste già
        existing_user = self.get_user_by_username(username)
        if existing_user:
            logger.warning(f"User {username} already exists")
            raise ValueError(f"User {username} already exists")

        # Crea un nuovo utente
        import uuid
        user = UserAccount(
            id=str(uuid.uuid4()),
            username=username,
            password_hash=self._hash_password(password),
            email=email,
            first_name=first_name,
            last_name=last_name,
            role=role
        )

        # Salva l'utente
        try:
            self.storage_backend.save_user(user)
        except Exception as e:
            logger.error(f"Error saving user {username}: {str(e)}")
            raise

        return user

    def update_user(self, user: UserAccount, password: Optional[str] = None) -> UserAccount:
        """
        Aggiorna un utente nel database locale.

        Args:
            user: Utente da aggiornare
            password: Nuova password (opzionale)

        Returns:
            Account utente aggiornato
        """
        logger.debug(f"Updating user {user.username}")

        # Aggiorna la password se specificata
        if password:
            user.password_hash = self._hash_password(password)

        # Aggiorna l'utente
        try:
            self.storage_backend.save_user(user)
        except Exception as e:
            logger.error(f"Error updating user {user.username}: {str(e)}")
            raise

        return user

    def _hash_password(self, password: str) -> str:
        """
        Calcola l'hash di una password.

        Args:
            password: Password da hashare

        Returns:
            Hash della password

        Note:
            In un'implementazione reale, si utilizzerebbero algoritmi più sicuri
            come bcrypt o PBKDF2 invece di un semplice SHA-256.
        """
        # Questa è una semplificazione; in produzione usare bcrypt o PBKDF2
        return hashlib.sha256(password.encode('utf-8')).hexdigest()