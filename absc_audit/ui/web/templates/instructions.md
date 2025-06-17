# Interfaccia Web per ABSC Audit System

Questa è l'interfaccia web per il sistema di audit ABSC, che consente di gestire target, eseguire controlli di sicurezza, visualizzare risultati e generare report.

## Requisiti

- Python 3.8 o superiore
- Pip (gestore pacchetti Python)
- Pacchetti Python elencati in `requirements.txt`

## Installazione

1. Crea un ambiente virtuale (opzionale ma consigliato):
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   # oppure
   venv\Scripts\activate     # Windows
   ```

2. Installa le dipendenze:
   ```bash
   pip install -r requirements.txt
   ```

3. Configura le variabili d'ambiente (opzionale):
   ```bash
   # Linux/macOS
   export SECRET_KEY="una-chiave-segreta-complessa"
   export PORT=5000
   export ENABLE_SCHEDULER=true
   
   # Windows
   set SECRET_KEY=una-chiave-segreta-complessa
   set PORT=5000
   set ENABLE_SCHEDULER=true
   ```

## Avvio dell'Applicazione

Per avviare l'applicazione in modalità di sviluppo:

```bash
python -m absc_audit.ui.web.app
```

Oppure tramite Flask:

```bash
export FLASK_APP=absc_audit.ui.web.app
export FLASK_ENV=development
flask run --host=0.0.0.0 --port=5000
```

L'applicazione sarà disponibile all'indirizzo `http://127.0.0.1:5000`.

## Struttura delle Directory

- `absc_audit/ui/web/`: Directory principale dell'interfaccia web
  - `app.py`: Applicazione Flask principale
  - `forms.py`: Definizioni dei form Flask-WTF
  - `models.py`: Modelli per Flask-Login
  - `utils.py`: Funzioni di utilità
  - `templates/`: Template HTML Jinja2
  - `static/`: File statici (CSS, JavaScript, immagini)

## Funzionalità Principali

1. **Dashboard**: Panoramica dei target, controlli e stato di conformità
2. **Target**: Gestione dei target di audit
3. **Controlli**: Visualizzazione dei controlli disponibili
4. **Audit**: Esecuzione di nuovi audit e pianificazione di audit automatici
5. **Report**: Generazione e visualizzazione di report di conformità
6. **Utenti**: Gestione degli utenti (admin)

## Configurazione Avanzata

### SQLite vs PostgreSQL

Per utilizzare PostgreSQL invece di SQLite, configura le seguenti variabili d'ambiente:

```bash
export USE_POSTGRESQL=true
export POSTGRESQL_DSN="postgresql://user:password@localhost:5432/absc_audit"
```

### Scheduler

Per abilitare lo scheduler che esegue automaticamente gli audit pianificati:

```bash
export ENABLE_SCHEDULER=true
```

### Notifiche Email

Per abilitare le notifiche email, configura:

```bash
export ENABLE_NOTIFICATIONS=true
export SMTP_SERVER=smtp.example.com
export SMTP_PORT=587
export SMTP_USERNAME=user@example.com
export SMTP_PASSWORD=password
export SMTP_USE_TLS=true
```

## Docker

Per eseguire l'applicazione in un container Docker:

```bash
docker build -t absc-audit-web .
docker run -d -p 5000:5000 --name absc-audit absc-audit-web
```

## Integrazione con Altri Sistemi

L'interfaccia web espone anche un'API REST che può essere utilizzata da altri sistemi per interagire con il sistema di audit. Vedere la documentazione dell'API per maggiori dettagli.