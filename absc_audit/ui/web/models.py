# absc_audit/ui/web/models.py

"""
Web Models - Modelli per l'interfaccia web.

Questo modulo definisce i modelli utilizzati nell'interfaccia web Flask.
"""

from flask_login import UserMixin
from absc_audit.storage.models import UserAccount


class User(UserMixin):
    """
    Classe User per Flask-Login.

    Questa classe incapsula UserAccount per l'uso con Flask-Login.
    """

    def __init__(self, id, username, role, enabled=True):
        self.id = id
        self.username = username
        self.role = role
        self.enabled = enabled

    @classmethod
    def from_user_account(cls, user_account: UserAccount) -> 'User':
        """
        Crea un User da un UserAccount.

        Args:
            user_account: Istanza di UserAccount

        Returns:
            Istanza di User
        """
        return cls(
            id=user_account.id,
            username=user_account.username,
            role=user_account.role,
            enabled=user_account.enabled
        )

    def is_active(self):
        """
        Verifica se l'utente è attivo.

        Returns:
            True se l'utente è attivo, False altrimenti
        """
        return self.enabled

    def is_admin(self):
        """
        Verifica se l'utente è un amministratore.

        Returns:
            True se l'utente è un amministratore, False altrimenti
        """
        return self.role == "admin"