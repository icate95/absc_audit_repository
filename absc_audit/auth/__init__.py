"""
Authentication Module - Modulo di autenticazione per il sistema di audit ABSC.

Questo pacchetto implementa il sistema di autenticazione per l'applicazione,
supportando sia autenticazione locale che LDAP/Active Directory.
"""

from absc_audit.auth.authentication_provider import AuthenticationProvider
from absc_audit.auth.local_authentication_provider import LocalAuthenticationProvider
from absc_audit.auth.ldap_authentication_provider import LDAPAuthenticationProvider
from absc_audit.auth.authentication_service import AuthenticationService
from absc_audit.auth.authentication_middleware import AuthenticationMiddleware
from absc_audit.auth.authentication_config import AuthenticationConfig, configure_authentication
from absc_audit.auth.ldap_config import (
    LDAPConfigBuilder,
    create_active_directory_config,
    create_openldap_config,
    create_freeipa_config
)

__all__ = [
    'AuthenticationProvider',
    'LocalAuthenticationProvider',
    'LDAPAuthenticationProvider',
    'AuthenticationService',
    'AuthenticationMiddleware',
    'AuthenticationConfig',
    'configure_authentication',
    'LDAPConfigBuilder',
    'create_active_directory_config',
    'create_openldap_config',
    'create_freeipa_config'
]