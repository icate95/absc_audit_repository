"""
Authentication Middleware - Middleware per l'autenticazione nelle API e interfacce web.

Questo modulo implementa middleware per l'autenticazione nelle API e
interfacce web, utilizzando il servizio di autenticazione.
"""

from typing import Dict, List, Optional, Any, Callable, Tuple
from functools import wraps
import base64
import json

from absc_audit.auth.authentication_service import AuthenticationService
from absc_audit.storage.models import UserAccount
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class AuthenticationMiddleware:
    """
    Middleware per l'autenticazione nelle API e interfacce web.

    Questa classe fornisce funzionalità di autenticazione e autorizzazione
    per API e interfacce web.
    """

    def __init__(self, auth_service: AuthenticationService):
        """
        Inizializza il middleware di autenticazione.

        Args:
            auth_service: Servizio di autenticazione
        """
        self.auth_service = auth_service
        self.session_store = {}  # In un'implementazione reale, si utilizzerebbe Redis o simili

    # ----- Middleware per Flask -----

    def flask_login_required(self, view_func):
        """
        Decorator per richiedere l'autenticazione in Flask.

        Args:
            view_func: Funzione vista da proteggere

        Returns:
            Funzione wrapper
        """
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            # Importa Flask
            try:
                from flask import request, session, redirect, url_for
            except ImportError:
                logger.error("Flask is not installed")
                return {"error": "Server configuration error"}, 500

            # Verifica se l'utente è autenticato nella sessione
            if 'user_id' not in session:
                logger.warning("User not authenticated in session")
                return redirect(url_for('login', next=request.url))

            # Ottieni l'utente dalla sessione
            user_id = session['user_id']
            user, provider = self._get_user_from_session(user_id)

            if not user:
                logger.warning(f"User with session ID {user_id} not found")
                session.pop('user_id', None)
                return redirect(url_for('login', next=request.url))

            # Aggiungi l'utente alla request
            kwargs['current_user'] = user

            return view_func(*args, **kwargs)

        return wrapped_view

    def flask_admin_required(self, view_func):
        """
        Decorator per richiedere ruolo admin in Flask.

        Args:
            view_func: Funzione vista da proteggere

        Returns:
            Funzione wrapper
        """
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            # Importa Flask
            try:
                from flask import request, session, redirect, url_for, abort
            except ImportError:
                logger.error("Flask is not installed")
                return {"error": "Server configuration error"}, 500

            # Verifica se l'utente è autenticato nella sessione
            if 'user_id' not in session:
                logger.warning("User not authenticated in session")
                return redirect(url_for('login', next=request.url))

            # Ottieni l'utente dalla sessione
            user_id = session['user_id']
            user, provider = self._get_user_from_session(user_id)

            if not user:
                logger.warning(f"User with session ID {user_id} not found")
                session.pop('user_id', None)
                return redirect(url_for('login', next=request.url))

            # Verifica il ruolo admin
            if user.role != 'admin':
                logger.warning(f"User {user.username} is not an admin")
                abort(403)  # Forbidden

            # Aggiungi l'utente alla request
            kwargs['current_user'] = user

            return view_func(*args, **kwargs)

        return wrapped_view

    def flask_authenticate(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """
        Autentica un utente e crea una sessione in Flask.

        Args:
            username: Nome utente
            password: Password

        Returns:
            Tuple with (success, session_id)
        """
        # Autentica l'utente
        success, user, provider = self.auth_service.authenticate(username, password)

        if not success or not user:
            logger.warning(f"Authentication failed for user {username}")
            return False, None

        # Crea una sessione
        session_id = self._create_session(user, provider)

        return True, session_id

    def flask_logout(self, session_id: str) -> bool:
        """
        Chiude una sessione in Flask.

        Args:
            session_id: ID della sessione

        Returns:
            True se la sessione è stata chiusa, False altrimenti
        """
        if session_id in self.session_store:
            del self.session_store[session_id]
            logger.debug(f"Session {session_id} closed")
            return True

        logger.warning(f"Session {session_id} not found")
        return False

    # ----- Middleware per API REST -----

    def api_auth_required(self, view_func):
        """
        Decorator per richiedere l'autenticazione in API REST.

        Args:
            view_func: Funzione vista da proteggere

        Returns:
            Funzione wrapper
        """
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            # Importa Flask
            try:
                from flask import request, jsonify
            except ImportError:
                logger.error("Flask is not installed")
                return {"error": "Server configuration error"}, 500

            # Ottieni le credenziali dall'header Authorization
            auth_header = request.headers.get('Authorization')

            if not auth_header:
                logger.warning("No Authorization header")
                return jsonify({"error": "Unauthorized"}), 401

            # Supporta sia l'autenticazione Basic che Bearer
            if auth_header.startswith('Basic '):
                # Basic Auth
                try:
                    auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                    username, password = auth_decoded.split(':', 1)

                    success, user, provider = self.auth_service.authenticate(username, password)

                    if not success or not user:
                        logger.warning(f"Basic Auth failed for user {username}")
                        return jsonify({"error": "Unauthorized"}), 401

                    # Aggiungi l'utente alla request
                    kwargs['current_user'] = user

                except Exception as e:
                    logger.error(f"Error processing Basic Auth: {str(e)}")
                    return jsonify({"error": "Unauthorized"}), 401

            elif auth_header.startswith('Bearer '):
                # Bearer Token (JWT o custom token)
                token = auth_header[7:]

                # Verifica il token e ottiene l'utente
                user, provider = self._validate_token(token)

                if not user:
                    logger.warning(f"Invalid Bearer token")
                    return jsonify({"error": "Unauthorized"}), 401

                # Aggiungi l'utente alla request
                kwargs['current_user'] = user

            else:
                logger.warning(f"Unsupported authentication method")
                return jsonify({"error": "Unauthorized"}), 401

            return view_func(*args, **kwargs)

        return wrapped_view

    def api_admin_required(self, view_func):
        """
        Decorator per richiedere ruolo admin in API REST.

        Args:
            view_func: Funzione vista da proteggere

        Returns:
            Funzione wrapper
        """
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            # Importa Flask
            try:
                from flask import request, jsonify
            except ImportError:
                logger.error("Flask is not installed")
                return {"error": "Server configuration error"}, 500

            # Ottieni le credenziali dall'header Authorization
            auth_header = request.headers.get('Authorization')

            if not auth_header:
                logger.warning("No Authorization header")
                return jsonify({"error": "Unauthorized"}), 401

            # Ottieni l'utente (riutilizziamo la logica del middleware auth_required)
            user = None

            if auth_header.startswith('Basic '):
                try:
                    auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                    username, password = auth_decoded.split(':', 1)

                    success, user, provider = self.auth_service.authenticate(username, password)

                    if not success or not user:
                        logger.warning(f"Basic Auth failed for user {username}")
                        return jsonify({"error": "Unauthorized"}), 401

                except Exception as e:
                    logger.error(f"Error processing Basic Auth: {str(e)}")
                    return jsonify({"error": "Unauthorized"}), 401

            elif auth_header.startswith('Bearer '):
                token = auth_header[7:]
                user, provider = self._validate_token(token)

                if not user:
                    logger.warning(f"Invalid Bearer token")
                    return jsonify({"error": "Unauthorized"}), 401

            else:
                logger.warning(f"Unsupported authentication method")
                return jsonify({"error": "Unauthorized"}), 401

            # Verifica il ruolo admin
            if not user or user.role != 'admin':
                logger.warning(f"User {user.username if user else 'Unknown'} is not an admin")
                return jsonify({"error": "Forbidden"}), 403

            # Aggiungi l'utente alla request
            kwargs['current_user'] = user

            return view_func(*args, **kwargs)

        return wrapped_view

    def generate_token(self, user: UserAccount) -> str:
        """
        Genera un token JWT per un utente.

        Args:
            user: Utente per cui generare il token

        Returns:
            Token JWT
        """
        # In un'implementazione reale, si utilizzerebbe una libreria JWT
        # Qui creiamo un semplice token personalizzato
        payload = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role,
            'exp': int(datetime.datetime.now().timestamp()) + 3600  # 1 ora
        }

        # Serializza e codifica il payload
        token_bytes = json.dumps(payload).encode('utf-8')
        token = base64.b64encode(token_bytes).decode('utf-8')

        # In un'implementazione reale, firmeremmo il token con un segreto
        # token = sign(token, secret_key)

        return token

    # ----- Metodi privati -----

    def _create_session(self, user: UserAccount, provider: str) -> str:
        """
        Crea una sessione per un utente.

        Args:
            user: Utente per cui creare la sessione
            provider: Provider di autenticazione utilizzato

        Returns:
            ID della sessione
        """
        import uuid
        session_id = str(uuid.uuid4())

        self.session_store[session_id] = {
            'user_id': user.id,
            'username': user.username,
            'provider': provider,
            'created_at': datetime.datetime.now().isoformat()
        }

        logger.debug(f"Session {session_id} created for user {user.username}")

        return session_id

    def _get_user_from_session(self, session_id: str) -> Tuple[Optional[UserAccount], Optional[str]]:
        """
        Ottiene un utente da una sessione.

        Args:
            session_id: ID della sessione

        Returns:
            Tuple with (user, provider)
        """
        session_data = self.session_store.get(session_id)

        if not session_data:
            logger.warning(f"Session {session_id} not found")
            return None, None

        username = session_data.get('username')
        provider = session_data.get('provider')

        if not username:
            logger.warning(f"Username not found in session {session_id}")
            return None, None

        # Ottieni l'utente dal servizio di autenticazione
        user, provider_name = self.auth_service.get_user_by_username(username)

        return user, provider_name

    def _validate_token(self, token: str) -> Tuple[Optional[UserAccount], Optional[str]]:
        """
        Valida un token JWT e ottiene l'utente associato.

        Args:
            token: Token JWT

        Returns:
            Tuple with (user, provider)
        """
        try:
            # Decodifica il token
            token_bytes = base64.b64decode(token)
            payload = json.loads(token_bytes.decode('utf-8'))

            # Verifica la scadenza
            exp = payload.get('exp', 0)
            if exp < datetime.datetime.now().timestamp():
                logger.warning(f"Token expired")
                return None, None

            # Ottieni l'utente dal payload
            username = payload.get('username')
            if not username:
                logger.warning(f"Username not found in token")
                return None, None

            # Ottieni l'utente dal servizio di autenticazione
            user, provider = self.auth_service.get_user_by_username(username)

            return user, provider

        except Exception as e:
            logger.error(f"Error validating token: {str(e)}")
            return None, None