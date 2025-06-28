"""
Secure Credential Management Module for the ABSC Audit System.

This module implements encryption mechanisms to protect
sensitive information using the cryptography library.
"""

from cryptography.fernet import Fernet
from typing import Union, Optional
import os
import base64


class SecureCredentialManager:
    """
    Credential manager with Fernet symmetric encryption.

    Provides methods to encrypt, decrypt, and securely manage
    sensitive credentials.
    """

    def __init__(self, key_path: Optional[str] = None):
        """
        Initialize the credential manager.

        Args:
            key_path: Path to the encryption key file.
                      If None, generates a new key.
        """
        if key_path and os.path.exists(key_path):
            with open(key_path, 'rb') as key_file:
                self.key = key_file.read()
        else:
            self.key = Fernet.generate_key()
            if key_path:
                os.makedirs(os.path.dirname(key_path), exist_ok=True)
                with open(key_path, 'wb') as key_file:
                    key_file.write(self.key)

        self.cipher_suite = Fernet(self.key)

    def encrypt_credential(self, credential: Union[str, bytes]) -> bytes:
        """
        Encrypt a credential.

        Args:
            credential: Credential to encrypt (string or bytes)

        Returns:
            Encrypted credential in bytes
        """
        # Convert to bytes if it's a string
        if isinstance(credential, str):
            credential = credential.encode('utf-8')

        return self.cipher_suite.encrypt(credential)

    def decrypt_credential(self, encrypted_credential: bytes) -> str:
        """
        Decrypt a credential.

        Args:
            encrypted_credential: Encrypted credential in bytes

        Returns:
            Original credential as a string
        """
        return self.cipher_suite.decrypt(encrypted_credential).decode('utf-8')

    @staticmethod
    def generate_safe_token(length: int = 32) -> str:
        """
        Generate a secure random token.

        Args:
            length: Token length in bytes

        Returns:
            Base64 encoded token
        """
        return base64.urlsafe_b64encode(os.urandom(length)).decode('utf-8')

    def __repr__(self) -> str:
        """
        Textual representation of the manager.

        Returns:
            String representing the instance
        """
        return f"SecureCredentialManager(key_hash={hash(self.key)})"