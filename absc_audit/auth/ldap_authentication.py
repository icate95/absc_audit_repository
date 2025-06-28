"""
LDAP Authentication Module for the ABSC Audit System.

Implements a flexible and configurable LDAP authenticator
to support different directory server types.
"""

from ldap3 import Server, Connection, ALL, SUBTREE, BASE
from typing import Dict, Optional, List, Any
import logging


class LDAPAuthenticator:
    """
    Configurable LDAP authenticator with support for multiple providers.

    Supports user authentication and search on LDAP/Active Directory servers.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the LDAP authenticator.

        Args:
            config: LDAP configuration dictionary with keys:
                - host: LDAP server address
                - port: Server port (default 389)
                - base_dn: Base DN for searches
                - bind_dn: Binding DN (optional)
                - bind_password: Binding password (optional)
                - type: Server type (active_directory, openldap, freeipa)
        """
        self.config = config
        self.server = Server(
            host=config['host'],
            port=config.get('port', 389),
            get_info=ALL
        )

        # Server-specific configurations
        self.server_type = config.get('type', 'generic').lower()
        self.base_dn = config['base_dn']
        self.bind_dn = config.get('bind_dn')
        self.bind_password = config.get('bind_password')

        # Logger to track operations and errors
        self.logger = logging.getLogger('absc_audit.ldap_authenticator')

    def _get_connection(self, user_dn: Optional[str] = None, password: Optional[str] = None) -> Connection:
        """
        Obtain an LDAP connection.

        Args:
            user_dn: User DN for authentication
            password: User password

        Returns:
            LDAP connection object
        """
        try:
            if user_dn and password:
                return Connection(self.server, user=user_dn, password=password)
            elif self.bind_dn and self.bind_password:
                return Connection(self.server, user=self.bind_dn, password=self.bind_password)
            else:
                return Connection(self.server)
        except Exception as e:
            self.logger.error(f"Error creating LDAP connection: {e}")
            raise

    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate a user against the LDAP server.

        Args:
            username: Username
            password: Password

        Returns:
            True if authentication succeeds, False otherwise
        """
        try:
            conn = self._get_connection()
            conn.bind()

            # User search based on server type
            search_filters = {
                'active_directory': f'(sAMAccountName={username})',
                'openldap': f'(uid={username})',
                'freeipa': f'(uid={username})',
                'generic': f'(cn={username})'
            }

            search_filter = search_filters.get(self.server_type, f'(cn={username})')

            conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                attributes=['dn', 'memberOf']
            )

            if not conn.entries:
                self.logger.warning(f"User not found: {username}")
                return False

            # Try authentication with user credentials
            user_dn = conn.entries[0].entry_dn
            auth_conn = Connection(self.server, user=user_dn, password=password)
            auth_result = auth_conn.bind()

            return auth_result

        except Exception as e:
            self.logger.error(f"Error during LDAP authentication: {e}")
            return False

    def get_user_groups(self, username: str) -> List[str]:
        """
        Retrieve groups the user is a member of.

        Args:
            username: Username

        Returns:
            List of groups
        """
        try:
            conn = self._get_connection()
            conn.bind()

            search_filters = {
                'active_directory': f'(sAMAccountName={username})',
                'openldap': f'(uid={username})',
                'freeipa': f'(uid={username})',
                'generic': f'(cn={username})'
            }

            search_filter = search_filters.get(self.server_type, f'(cn={username})')

            conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                attributes=['memberOf']
            )

            if not conn.entries:
                return []

            # Extract group names
            groups = [group.split(',')[0].split('=')[1] for group in conn.entries[0]['memberOf']]
            return groups

        except Exception as e:
            self.logger.error(f"Error retrieving groups: {e}")
            return []