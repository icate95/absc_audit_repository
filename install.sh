#!/bin/bash

# Funzione per controllare se un comando esiste
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Colori per l'output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Controllo prerequisiti
check_prerequisites() {
    echo -e "${YELLOW}Controllo dei prerequisiti...${NC}"

    # Controllo Python
    if ! command_exists python3; then
        echo -e "${RED}Errore: Python 3 non installato${NC}"
        exit 1
    fi

    # Controllo pip
    if ! command_exists pip3; then
        echo -e "${RED}Errore: pip non installato${NC}"
        exit 1
    fi

    # Controllo virtualenv
    if ! command_exists virtualenv; then
        echo -e "${YELLOW}Installazione di virtualenv...${NC}"
        pip3 install virtualenv
    fi
}

# Configurazione ambiente virtuale
setup_virtual_env() {
    echo -e "${YELLOW}Configurazione ambiente virtuale...${NC}"

    # Nome della directory dell'ambiente virtuale
    VENV_NAME="absc_audit_venv"

    # Creazione ambiente virtuale
    python3 -m virtualenv "$VENV_NAME"

    # Attivazione ambiente virtuale
    source "$VENV_NAME/bin/activate"
}

# Installazione dipendenze
install_dependencies() {
    echo -e "${YELLOW}Installazione dipendenze...${NC}"

    # Upgrade pip
    pip install --upgrade pip

    # Installazione dipendenze
    pip install -r requirements.txt

    # Installazione del pacchetto in modalità sviluppo
    pip install -e .
}

# Inizializzazione database
initialize_database() {
    echo -e "${YELLOW}Inizializzazione database...${NC}"

    # Comando per inizializzare il database
    python -m absc_audit init-db
}

# Esecuzione test
run_tests() {
    echo -e "${YELLOW}Esecuzione test...${NC}"

    # Esecuzione test
    python -m pytest tests/
}

# Main
main() {
    check_prerequisites
    setup_virtual_env
    install_dependencies
    initialize_database
    run_tests

    echo -e "${GREEN}Installazione completata con successo!${NC}"
    echo -e "${YELLOW}Per utilizzare ABSC Audit System, attiva l'ambiente virtuale:${NC}"
    echo -e "source absc_audit_venv/bin/activate"
}

# Esecuzione dello script
main