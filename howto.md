Utilizzo del sistema
Ora il sistema è pronto per essere utilizzato. Ecco alcuni esempi di utilizzo dalla linea di comando:

Aggiungere un target:
```
python -m absc_audit add-target --name "Server Web" --hostname "192.168.1.10" --os linux --description "Server web principale" --group "Produzione" --tags "web,linux,produzione"
```

Elencare i target:
```
python -m absc_audit list-targets
```

Elencare i controlli disponibili:
```
python -m absc_audit list-checks
```

Eseguire un controllo specifico:
```
python -m absc_audit run-check --target "Server Web" --check "1.1.1-1.1.4"
```

Eseguire un audit completo:
```
python -m absc_audit run-audit --target "Server Web" --parallel
```

Generare un report:
```
python -m absc_audit generate-report --target "Server Web" --format html --out
```



# Sistema di Audit Sicurezza ABSC

Un sistema completo per l'automazione degli audit di sicurezza basati sulle misure minime ABSC (AgID Basic Security Controls).

## Introduzione

Questo sistema permette di eseguire controlli automatizzati di sicurezza su diversi target (server, workstation, ecc.) per verificare la conformità alle misure minime di sicurezza ABSC. Il sistema è progettato per essere modulare, estensibile e facilmente configurabile.

## Installazione

### Prerequisiti

- Python 3.8 o superiore
- Virtualenv (consigliato)

### Installazione da sorgente

1. Clona il repository o estrai l'archivio in una directory a tua scelta
2. Crea un ambiente virtuale e attivalo:

```bash
python -m venv absc_audit_system_venv
source absc_audit_system_venv/bin/activate  # su Linux/macOS
absc_audit_system_venv\Scripts\activate      # su Windows
```

3. Installa il pacchetto in modalità sviluppo:

```bash
cd absc_audit_system
pip install -e .
```

4. Inizializza il database:

```bash
python -m absc_audit init-db
```

## Utilizzo

Il sistema può essere utilizzato tramite interfaccia a linea di comando (CLI).

### Comandi CLI

#### Inizializzazione del database

Prima di utilizzare il sistema, è necessario inizializzare il database:

```bash
python -m absc_audit init-db
```

#### Gestione dei Target

**Aggiungere un target**:

```bash
python -m absc_audit add-target --name "Nome Target" --hostname "indirizzo-ip-o-hostname" --os linux|windows --description "Descrizione" --group "Gruppo" --tags "tag1,tag2,tag3"
```

**Elencare i target**:

```bash
python -m absc_audit list-targets
```

**Eliminare un target**:

```bash
python -m absc_audit delete-target --id "ID-target"
```

#### Gestione dei Controlli

**Elencare i controlli disponibili**:

```bash
python -m absc_audit list-checks
```

todo: aggiungere comando per visualizzare lo specifico controllo che esegue un controllo

**Elencare i controlli di una categoria specifica**:

```bash
python -m absc_audit list-checks --category "Inventory"
```

#### Esecuzione di Audit

**Eseguire un singolo controllo su un target**:

```bash
python -m absc_audit run-check --target "Nome-Target" --check "1.1.1-1.1.4"
```

**Eseguire un audit completo su un target**:

```bash
python -m absc_audit run-audit --target "Nome-Target"
```

**Eseguire un audit di una categoria specifica**:

```bash
python -m absc_audit run-audit --target "Nome-Target" --category "Inventory"
```

**Eseguire un audit con una priorità specifica**:

```bash
python -m absc_audit run-audit --target "Nome-Target" --priority 1
```

todo: comando che chiede tutti i parametri prima di iniziare l'esecuzione

**NOTA IMPORTANTE**: L'esecuzione parallela può causare problemi con SQLite. Se riscontri errori, evita di usare il flag `--parallel` o utilizza PostgreSQL come backend.

#### Gestione dei Risultati

**Elencare i risultati degli audit**:

```bash
python -m absc_audit list-results
```

**Elencare i risultati di un target specifico**:

```bash
python -m absc_audit list-results --target "Nome-Target"
```

**Elencare i risultati più recenti**:

```bash
python -m absc_audit list-results --latest
```

#### Generazione di Report

**Generare un report in formato HTML**:

```bash
python -m absc_audit generate-report --target "Nome-Target" --format html --output report.html
```

**Formati supportati**: json, csv, html, pdf

#### Autenticazione

Elenca i controlli per verificare che i nuovi siano registrati
```
python -m absc_audit list-checks --category "Authentication"
``` 
Testa uno dei nuovi controlli su un target
```
python -m absc_audit run-check --target "Nome Target" --check "2.1.1-2.1.2"
```

#### Controlli accesso amministrativo

 Elenca i controlli per verificare che i nuovi siano registrati
```
python -m absc_audit list-checks --category "AdminAccess"
```

 Testa uno dei nuovi controlli su un target
```
python -m absc_audit run-check --target "Nome Target" --check "5.1.1-5.1.2"
```

#### Controlli backup
 Elenca i controlli per verificare che i nuovi siano registrati
```
python -m absc_audit list-checks --category "Backup"
```

 Testa uno dei nuovi controlli su un target
```
python -m absc_audit run-check --target "Nome Target" --check "13.1.1-13.1.3"
```

#### Controlli encryptions
Elenca i controlli per verificare che i nuovi siano registrati
```
python -m absc_audit list-checks --category "Encryption"
```
Testa uno dei nuovi controlli su un target
```
python -m absc_audit run-check --target "Nome Target" --check "3.3.1-3.3.2"
```


# Elenca i controlli per verificare che i nuovi siano registrati
python -m absc_audit list-checks --category "Logging"

# Testa uno dei nuovi controlli su un target
python -m absc_audit run-check --target "Nome Target" --check "10.1.1-10.1.2"


## interfaccia web
Dalla directory radice del progetto
```python -m absc_audit.ui.web.app```



## Struttura del Progetto

Il progetto è organizzato nei seguenti moduli principali:

- **core**: Implementazione del motore di audit, risultati e schedulazione
- **checks**: Implementazione dei controlli ABSC specifici
- **connectors**: Connettori per interagire con i sistemi target
- **storage**: Gestione della persistenza dei dati
- **ui**: Interfacce utente (CLI e web)
- **utils**: Utilità varie

## Controlli Implementati

Il sistema implementa i seguenti controlli ABSC:

1. **Inventario (ABSC 1.x)**:
   - Inventario delle risorse attive (1.1.1-1.1.4)
   - Rilevamento dispositivi di rete (1.1.3-1.1.4)
   - Monitoraggio dei log DHCP (1.2.1-1.2.2)

2. **Vulnerabilità (ABSC 4.x)**:
   - Ricerca periodica delle vulnerabilità (4.1.1-4.1.3)
   - Gestione delle patch di sicurezza (4.5.1-4.5.2)

3. **Malware (ABSC 8.x)**:
   - Protezione anti-malware (8.1.1-8.1.3)
   - Prevenzione dell'esecuzione (8.2.1-8.2.3)
   - 
4. **Autenticazione (ABSC 2.x)**:
   - Policy di password (2.1.1-2.1.2)
   - Account amministrativi (2.4.1-2.4.2)

5. **Accesso Amministrativo (ABSC 5.x)**:
   - Utilizzo privilegiato delle utenze amministrative (5.1.1-5.1.2)
   - Accesso amministrativo remoto (5.7.1-5.7.4)

6. **Backup (ABSC 13.x)**:
   - Procedure di backup (13.1.1-13.1.3)
   - Test di ripristino (13.2.1-13.2.2)

7. **Cifratura (ABSC 3.x)**:
   - Cifratura dei dati critici (3.3.1-3.3.2)
   - Cifratura dei dati in transito (3.1.1-3.2.1)

8. **Logging (ABSC 10.x)**:
   - Configurazione del logging (10.1.1-10.1.2)
   - Analisi dei log (10.3.1-10.3.2)



## Estensione del Sistema

### Aggiungere Nuovi Controlli

Per aggiungere un nuovo controllo:

1. Crea una nuova classe che estende `BaseCheck` in uno dei moduli esistenti o crea un nuovo modulo
2. Implementa il metodo `run()` che esegue la logica del controllo
3. Registra il controllo nel `CheckRegistry`

Esempio di base:

```python
from absc_audit.checks.base import BaseCheck

class MyNewCheck(BaseCheck):
    ID = "x.y.z"
    NAME = "Nome del controllo"
    DESCRIPTION = "Descrizione del controllo"
    QUESTION = "Domanda del controllo?"
    POSSIBLE_ANSWERS = ["Sì", "No"]
    CATEGORY = "MiaCategoria"
    PRIORITY = 2  # 1=alta, 2=media, 3=bassa
    
    def run(self, target, params=None):
        result = self.prepare_result()
        
        # Implementa la logica del controllo
        
        result['status'] = "Sì"  # o "No"
        result['score'] = 100  # o altro valore
        result['details'] = {...}  # dettagli del controllo
        
        return result
```

### Aggiungere Nuovi Connettori

Per aggiungere un nuovo connettore:

1. Crea una nuova classe che estende `BaseConnector`
2. Implementa i metodi richiesti per la connessione e l'interazione con il target

## Troubleshooting

### Errori di SQLite in modalità parallela

SQLite ha limitazioni quando viene utilizzato in più thread contemporaneamente. Se riscontri errori durante l'esecuzione parallela, hai queste opzioni:

1. **Evitare l'esecuzione parallela**: Non utilizzare il flag `--parallel`
2. **Utilizzare PostgreSQL**: Configura il sistema per utilizzare PostgreSQL invece di SQLite
3. **Modificare SQLiteStorage**: Aggiungi un meccanismo di lock o crea una connessione per thread

### Modifiche consigliate a SQLiteStorage per il multi-threading

Se vuoi supportare meglio il multi-threading, modifica il file `absc_audit/storage/sqlite.py` come segue:

```python
import sqlite3
import threading

class SQLiteStorage:
    # ...
    
    # Aggiungi un local storage per thread
    _thread_local = threading.local()
    
    def _connect(self):
        """Stabilisce una connessione al database."""
        try:
            # Crea una connessione per ogni thread
            if not hasattr(self._thread_local, 'conn') or self._thread_local.conn is None:
                self._thread_local.conn = sqlite3.connect(self.db_path)
                # Abilita il supporto alle foreign key
                self._thread_local.conn.execute("PRAGMA foreign_keys = ON")
                # Configura il ritorno di dict invece di tuple
                self._thread_local.conn.row_factory = sqlite3.Row
                self._thread_local.cursor = self._thread_local.conn.cursor()
            
            self.conn = self._thread_local.conn
            self.cursor = self._thread_local.cursor
        except sqlite3.Error as e:
            logger.error(f"Error connecting to SQLite database: {str(e)}")
            raise
    
    def _disconnect(self):
        """Chiude la connessione al database."""
        # Non chiudiamo realmente la connessione per ogni operazione
        # La conserviamo nel thread_local storage
        pass
    
    def close(self):
        """Chiude tutte le connessioni."""
        try:
            if hasattr(self._thread_local, 'conn') and self._thread_local.conn:
                self._thread_local.conn.close()
                self._thread_local.conn = None
                self._thread_local.cursor = None
        except sqlite3.Error as e:
            logger.error(f"Error closing SQLite connection: {str(e)}")
```

## Configurazione Avanzata

### Utilizzo di PostgreSQL

Per utilizzare PostgreSQL invece di SQLite, modifica le impostazioni nel file `absc_audit/config/settings.py`:

```python
# Configurazione database
self.use_postgresql = True
self.postgresql_dsn = 'postgresql://username:password@localhost:5432/absc_audit'
```

E assicurati di aver installato il driver PostgreSQL:

```bash
pip install psycopg2-binary
```

## Licenza

Questo progetto è rilasciato sotto licenza MIT.