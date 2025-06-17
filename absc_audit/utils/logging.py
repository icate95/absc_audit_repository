# absc_audit/utils/logging.py

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional

from absc_audit.config.settings import Settings


def setup_logger(name: str, settings: Optional[Settings] = None) -> logging.Logger:
    """
    Configura e restituisce un logger.

    Args:
        name: Nome del logger
        settings: Configurazioni del sistema (opzionale)

    Returns:
        Logger configurato
    """
    # Crea un'istanza di Settings se non fornita
    settings = settings or Settings()

    # Crea il logger
    logger = logging.getLogger(name)
    logger.setLevel(settings.log_level)

    # Rimuovi gli handler esistenti per evitare duplicazione
    if logger.handlers:
        logger.handlers.clear()

    # Formattatore per il logging
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Handler per la console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Handler per il file di log (se specificato)
    if settings.log_file:
        # Assicurati che la directory esista
        log_dir = os.path.dirname(settings.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        # Crea l'handler di file
        file_handler = RotatingFileHandler(
            settings.log_file,
            maxBytes=settings.log_max_size,
            backupCount=settings.log_backup_count
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger