# Sistema di autenticazione per ABSC Audit

Questo documento descrive il sistema di autenticazione implementato nel sistema di audit ABSC, incluse le istruzioni per l'integrazione con Active Directory e altri provider LDAP.

## Panoramica

Il sistema di autenticazione supporta due modalità principali:

1. **Autenticazione locale**: Gli utenti sono memorizzati nel database locale dell'applicazione
2. **Autenticazione LDAP/AD**: Gli utenti sono autenticati tramite un server LDAP esterno o Active Directory

È possibile abilitare entrambe le modalità contemporaneamente, con priorità configurabili.

## Architettura

Il sistema è composto dai seguenti componenti principali:

- **Authentication Provider**: Interfaccia di base per i diversi metodi di autenticazione
- **Authentication Service**: Coordina i diversi provider e gestisce la logica di autenticazione
- **Authentication Middleware**: Fornisce funzionalità di autenticazione e autorizzazione per API e interfacce web
- **LDAP Authenticator**: Gestisce l'autenticazione specifica tramite LDAP/AD

## Configurazione

### Configurazione di base

Per configurare il sistema di autenticazione:

```python
from absc_audit.auth import AuthenticationConfig
from absc_audit.storage.sqlite import SQLiteStorage
from absc_audit.config.settings import Settings

# Inizializza lo storage e le impostazioni
settings = Settings()
storage = SQLiteStorage(settings)

# Crea una configurazione di autenticazione
auth_config = AuthenticationConfig(storage, settings)

# Configura autenticazione locale
auth_config.configure_local_auth(priority=10)

# Crea il middleware di autenticazione
auth_middleware = auth_config.build_middleware()

# Crea un utente amministratore locale
auth_config.create_admin_user(
    username="admin",
    password="password123",
    email="admin@example.com"
)
```

### Configurazione LDAP/AD

Per configurare l'autenticazione LDAP/AD:

```python
from absc_audit.auth import create_active_directory_config

# Crea la configurazione per Active Directory
ad_config = create_active_directory_config(
    server_uri="ldap://ad.example.com:389",
    domain="example.com",
    bind_user="ldapuser",
    bind_password="ldappassword",
    use_tls=True
)

# Aggiungi il provider LDAP al sistema di autenticazione
auth_config.configure_ldap_auth(ad_config, priority=20)
```

### Supporto per altri server LDAP

Il sistema supporta anche altri server LDAP come OpenLDAP e FreeIPA:

```python
from absc_audit.auth import create_openldap_config, create_freeipa_config

# OpenLDAP
openldap_config = create_openldap_config(
    server_uri="ldap://ldap.example.org:389",
    base_dn="dc=example,dc=org",
    bind_dn="cn=admin,dc=example,dc=org",
    bind_password="ldappassword",
    use_tls=True
)

# FreeIPA
freeipa_config = create_freeipa_config(
    server_uri="ldap://ipa.example.net:389",
    domain="example.net",
    bind_user="admin",
    bind_password="password",
    use_tls=True
)
```

### Configurazione personalizzata

Per configurazioni LDAP più complesse, è possibile utilizzare il builder:

```python
from absc_audit.auth import LDAPConfigBuilder

custom_config = LDAPConfigBuilder("ldap://ldap.custom.net:389") \
    .with_base_dn("o=Company,c=US") \
    .with_user_search(
        user_search_base="ou=People,o=Company,c=US",
        user_search_filter="(&(objectClass=person)(uid={username}))"
    ) \
    .with_group_search(
        group_search_base="ou=Groups,o=Company,c=US",
        group_search_filter="(&(objectClass=groupOfNames)(member={user_dn}))"
    ) \
    .with_admin_group("cn=Administrators,ou=Groups,o=Company,c=US") \
    .with_user_group("cn=Users,ou=Groups,o=Company,c=US") \
    .with_bind_credentials(
        "cn=Directory Manager,o=Company,c=US",
        "secret"
    ) \
    .with_tls(True) \
    .with_attribute_mapping({
        'username': 'uid',
        'email': 'mail',
        'first_name': 'givenName',
        'last_name': 'sn'
    }) \
    .build()
```

## Integrazione con interfacce web

### Integrazione con Flask

```python
from flask import Flask, request, session, redirect, url_for

# Crea l'app Flask
app = Flask(__name__)
app.secret_key = 'your-secret-key'

# Rotte protette
@app.route('/')
@auth_middleware.flask_login_required
def index(current_user):
    return f'Hello, {current_user.username}!'

@app.route('/admin')
@auth_middleware.flask_admin_required
def admin(current_user):
    return f'Admin area for {current_user.username}'

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        success, session_id = auth_middleware.flask_authenticate(username, password)
        
        if success:
            session['user_id'] = session_id
            return redirect(url_for('index'))
    
    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    if 'user_id' in session:
        auth_middleware.flask_logout(session['user_id'])
        session.pop('user_id', None)
    
    return redirect(url_for('login'))
```

### Integrazione con API REST

```python
@app.route('/api/data')
@auth_middleware.api_auth_required
def api_data(current_user):
    return jsonify({
        'message': f'Hello, {current_user.username}!',
        'data': get_user_data(current_user.id)
    })

@app.route('/api/admin')
@auth_middleware.api_admin_required
def api_admin(current_user):
    return jsonify({
        'message': f'Admin API for {current_user.username}',
        'admin_data': get_admin_data()
    })
```

## Test della configurazione LDAP

Per testare la configurazione LDAP, è possibile utilizzare lo script `test_ldap_auth.py`:

```bash
# Test Active Directory
python test_ldap_auth.py --ad --server ldap://ad.example.com:389 --domain example.com --bind-user ldapuser --test-user testuser

# Test OpenLDAP
python test_ldap_auth.py --openldap --server ldap://ldap.example.org:389 --base-dn "dc=example,dc=org" --bind-dn "cn=admin,dc=example,dc=org" --bind-user admin --test-user testuser

# Test FreeIPA
python test_ldap_auth.py --freeipa --server ldap://ipa.example.net:389 --domain example.net --bind-user admin --test-user testuser
```

## Risoluzione dei problemi

### Problemi di connessione LDAP

- Verificare che il server LDAP sia raggiungibile dalla rete
- Controllare che le credenziali di bind siano corrette
- Assicurarsi che il protocollo TLS sia configurato correttamente
- Verificare che i certificati siano validi e attendibili

### Problemi di autenticazione

- Verificare che il filtro di ricerca utenti sia corretto per il server LDAP
- Controllare che la mappatura degli attributi sia corretta
- Verificare che l'utente appartenga ai gruppi corretti
- Controllare i log per errori specifici

## Sicurezza

### Best Practices

- Utilizzare sempre TLS per la connessione LDAP
- Utilizzare un utente di bind con privilegi minimi
- Salvare le password di bind in modo sicuro (variabili d'ambiente o secret manager)
- Configurare l'autenticazione locale di fallback per gli amministratori
- Implementare il blocco degli account dopo tentativi falliti
- Utilizzare timeout di sessione appropriati

### Considerazioni sulla privacy

- Rispettare le normative sulla privacy quando si sincronizzano dati utente da LDAP
- Limitare gli attributi utente importati a quelli necessari
- Considerare la memorizzazione temporanea vs. permanente degli utenti LDAP