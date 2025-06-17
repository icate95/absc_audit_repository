"""
Storage Models - Definizione dei modelli dati per il sistema di audit ABSC.

Questo modulo implementa i modelli dati utilizzati dal sistema
per rappresentare target, controlli e risultati.
"""

import datetime
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union


@dataclass
class Target:
    """
    Rappresenta un target su cui eseguire gli audit.

    Un target può essere un server, un dispositivo di rete o qualsiasi
    endpoint su cui è necessario eseguire controlli di sicurezza.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    hostname: str = ""
    ip_address: str = ""
    os_type: str = ""  # linux, windows, macos, etc.
    os_version: str = ""
    description: str = ""
    group: str = ""
    tags: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    updated_at: datetime.datetime = field(default_factory=datetime.datetime.now)

    def __post_init__(self):
        """Validazione e impostazione di valori predefiniti."""
        if not self.name and self.hostname:
            self.name = self.hostname
        elif not self.name and self.ip_address:
            self.name = self.ip_address

    def to_dict(self) -> Dict:
        """Converte il target in un dizionario serializzabile."""
        return {
            "id": self.id,
            "name": self.name,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "os_type": self.os_type,
            "os_version": self.os_version,
            "description": self.description,
            "group": self.group,
            "tags": self.tags,
            "attributes": self.attributes,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Target':
        """Crea un target da un dizionario."""
        # Converte le date da stringa a datetime
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.datetime.fromisoformat(data['created_at'])
        if 'updated_at' in data and isinstance(data['updated_at'], str):
            data['updated_at'] = datetime.datetime.fromisoformat(data['updated_at'])

        return cls(**data)


@dataclass
class AuditCheck:
    """
    Rappresenta un controllo di audit ABSC.

    Questa classe contiene i metadati di un controllo, come ID ABSC,
    descrizione, domanda e possibili risposte.
    """

    id: str  # ID ABSC (es. "1.1.1-1.1.4")
    name: str
    description: str
    question: str
    possible_answers: List[str]
    category: str = ""
    priority: int = 3  # 1 (alta), 2 (media), 3 (bassa)
    enabled: bool = True
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Converte il controllo in un dizionario serializzabile."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "question": self.question,
            "possible_answers": self.possible_answers,
            "category": self.category,
            "priority": self.priority,
            "enabled": self.enabled,
            "params": self.params
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'AuditCheck':
        """Crea un controllo da un dizionario."""
        return cls(**data)


@dataclass
class AuditResult:
    """
    Rappresenta il risultato di un controllo di audit su un target.

    Questa classe contiene tutte le informazioni sul risultato di un controllo,
    inclusi stato, punteggio, dettagli e dati grezzi.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    check_id: str = ""
    target_id: str = ""
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)
    processed_at: Optional[datetime.datetime] = None
    status: Optional[str] = None
    score: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> Dict:
        """Converte il risultato in un dizionario serializzabile."""
        return {
            "id": self.id,
            "check_id": self.check_id,
            "target_id": self.target_id,
            "timestamp": self.timestamp.isoformat(),
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
            "status": self.status,
            "score": self.score,
            "details": self.details,
            "raw_data": self.raw_data,
            "notes": self.notes
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'AuditResult':
        """Crea un risultato da un dizionario."""
        # Converte le date da stringa a datetime
        if 'timestamp' in data and isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.datetime.fromisoformat(data['timestamp'])
        if 'processed_at' in data and isinstance(data['processed_at'], str) and data['processed_at']:
            data['processed_at'] = datetime.datetime.fromisoformat(data['processed_at'])

        return cls(**data)


@dataclass
class AuditReport:
    """
    Rappresenta un report che aggrega i risultati di più controlli.

    Questa classe contiene informazioni aggregate su più risultati di audit,
    inclusi statistiche di conformità e metriche generali.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    generated_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    target_ids: List[str] = field(default_factory=list)
    check_ids: List[str] = field(default_factory=list)
    compliance_stats: Dict[str, Any] = field(default_factory=dict)
    result_summary: Dict[str, Any] = field(default_factory=dict)
    result_ids: List[str] = field(default_factory=list)
    format: str = "json"  # json, csv, html, pdf

    def to_dict(self) -> Dict:
        """Converte il report in un dizionario serializzabile."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "generated_at": self.generated_at.isoformat(),
            "target_ids": self.target_ids,
            "check_ids": self.check_ids,
            "compliance_stats": self.compliance_stats,
            "result_summary": self.result_summary,
            "result_ids": self.result_ids,
            "format": self.format
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'AuditReport':
        """Crea un report da un dizionario."""
        # Converte le date da stringa a datetime
        if 'generated_at' in data and isinstance(data['generated_at'], str):
            data['generated_at'] = datetime.datetime.fromisoformat(data['generated_at'])

        return cls(**data)


@dataclass
class ScheduledAudit:
    """
    Rappresenta un audit pianificato.

    Questa classe contiene informazioni su un audit pianificato,
    inclusi target, controlli, frequenza e stato.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    target_ids: List[str] = field(default_factory=list)
    check_ids: List[str] = field(default_factory=list)
    frequency: str = "weekly"  # daily, weekly, monthly
    day_of_week: Optional[int] = None  # 0-6 (lunedì-domenica) per frequenza settimanale
    day_of_month: Optional[int] = None  # 1-31 per frequenza mensile
    hour: int = 0  # 0-23
    minute: int = 0  # 0-59
    enabled: bool = True
    last_run: Optional[datetime.datetime] = None
    next_run: Optional[datetime.datetime] = None
    notify_on_completion: bool = False
    notify_email: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Converte l'audit pianificato in un dizionario serializzabile."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "target_ids": self.target_ids,
            "check_ids": self.check_ids,
            "frequency": self.frequency,
            "day_of_week": self.day_of_week,
            "day_of_month": self.day_of_month,
            "hour": self.hour,
            "minute": self.minute,
            "enabled": self.enabled,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "notify_on_completion": self.notify_on_completion,
            "notify_email": self.notify_email,
            "params": self.params
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'ScheduledAudit':
        """Crea un audit pianificato da un dizionario."""
        # Converte le date da stringa a datetime
        if 'last_run' in data and isinstance(data['last_run'], str) and data['last_run']:
            data['last_run'] = datetime.datetime.fromisoformat(data['last_run'])
        if 'next_run' in data and isinstance(data['next_run'], str) and data['next_run']:
            data['next_run'] = datetime.datetime.fromisoformat(data['next_run'])

        return cls(**data)


@dataclass
class UserAccount:
    """
    Rappresenta un account utente per l'accesso al sistema.

    Questa classe contiene informazioni su un utente del sistema di audit,
    inclusi credenziali, permessi e dettagli personali.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    username: str = ""
    password_hash: str = ""
    email: str = ""
    first_name: str = ""
    last_name: str = ""
    role: str = "user"  # admin, user, viewer
    enabled: bool = True
    last_login: Optional[datetime.datetime] = None
    created_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    updated_at: datetime.datetime = field(default_factory=datetime.datetime.now)
    preferences: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Converte l'account utente in un dizionario serializzabile."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "role": self.role,
            "enabled": self.enabled,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "preferences": self.preferences
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'UserAccount':
        """Crea un account utente da un dizionario."""
        # Rimuovi password_hash dal dizionario per sicurezza se presente nel to_dict
        if 'password_hash' not in data:
            data['password_hash'] = ""

        # Converte le date da stringa a datetime
        for date_field in ['last_login', 'created_at', 'updated_at']:
            if date_field in data and isinstance(data[date_field], str) and data[date_field]:
                data[date_field] = datetime.datetime.fromisoformat(data[date_field])

        return cls(**data)