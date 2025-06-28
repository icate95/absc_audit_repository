"""
Storage Models - Data model definition for the ABSC audit system.

This module implements the data models used by the system
to represent targets, controls and results.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import datetime
import uuid
import json


@dataclass
class Target:
    """
    Represents a target on which to perform audits.

    A target can be a server, a network device, or any endpoint on which security checks need to be performed.
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
        """Validation and setting default values."""
        if not self.name and self.hostname:
            self.name = self.hostname
        elif not self.name and self.ip_address:
            self.name = self.ip_address

    def to_dict(self) -> Dict:
        """Converts the target into a serializable dictionary."""
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
        """Create a target from a dictionary."""
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.datetime.fromisoformat(data['created_at'])
        if 'updated_at' in data and isinstance(data['updated_at'], str):
            data['updated_at'] = datetime.datetime.fromisoformat(data['updated_at'])

        return cls(**data)

@dataclass
class AuditCheck:
    """
    Represents an ABSC audit control.

    This class contains metadata about a control, such as ABSC ID,
    description, question, and possible answers.
    """

    id: str  # ABSC ID (e.g. "1.1.1-1.1.4")
    name: str
    description: str
    question: str
    possible_answers: List[str]
    category: str = ""
    priority: int = 3  # 1 (high), 2 (medium), 3 (low)
    enabled: bool = True
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Converts the control into a serializable dictionary."""
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
        """Create a control from a dictionary."""
        return cls(**data)

@dataclass
class AuditResult:
    """
    Represents the result of an audit check on a target.

    This class contains all the information about the result of a check,
    including status, score, details, and raw data.
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
        """Converts the result into a serializable dictionary."""
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
        """Create a result from a dictionary."""
        # Converte le date da stringa a datetime
        if 'timestamp' in data and isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.datetime.fromisoformat(data['timestamp'])
        if 'processed_at' in data and isinstance(data['processed_at'], str) and data['processed_at']:
            data['processed_at'] = datetime.datetime.fromisoformat(data['processed_at'])

        return cls(**data)

@dataclass
class AuditReport:
    """
    Represents a report that aggregates the results of multiple audits.

    This class contains aggregate information about multiple audit results,
    including compliance statistics and general metrics.
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
        """Converts the report into a serializable dictionary."""
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
        """Create a report from a dictionary."""
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
        """Converts the report into a serializable dictionary."""
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
        """Create a report from a dictionary."""
        if 'last_run' in data and isinstance(data['last_run'], str) and data['last_run']:
            data['last_run'] = datetime.datetime.fromisoformat(data['last_run'])
        if 'next_run' in data and isinstance(data['next_run'], str) and data['next_run']:
            data['next_run'] = datetime.datetime.fromisoformat(data['next_run'])

        return cls(**data)

@dataclass
class UserAccount:
    """
    Represents a scheduled audit.

    This class contains information about a scheduled audit,
    including targets, controls, frequency, and status.
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
        """Converts the report into a serializable dictionary."""
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
        """Create a report from a dictionary."""
        if 'password_hash' not in data:
            data['password_hash'] = ""

        for date_field in ['last_login', 'created_at', 'updated_at']:
            if date_field in data and isinstance(data[date_field], str) and data[date_field]:
                data[date_field] = datetime.datetime.fromisoformat(data[date_field])

        return cls(**data)

@dataclass
class NetworkScan:
    """
    Represents a single network scan.

    Contains metadata about the scan, including parameters,
    network ranges scanned, and overall results.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Network Scan"
    description: Optional[str] = None
    start_time: datetime = field(default_factory=datetime.datetime.now)
    end_time: Optional[datetime] = None
    network_ranges: List[str] = field(default_factory=list)
    scan_parameters: Dict = field(default_factory=dict)
    total_devices: int = 0
    total_open_ports: int = 0
    total_vulnerabilities: int = 0

    # Nuovi campi per informazioni di rete globali
    total_subnets: int = 0  # Numero di subnet rilevate
    network_topology: Dict[str, Any] = field(default_factory=dict)  # Topologia di rete
    network_protocols: List[str] = field(default_factory=list)  # Protocolli rilevati
    network_services_summary: Dict[str, int] = field(default_factory=dict)  # Riepilogo servizi

    # Statistiche di sicurezza avanzate
    critical_vulnerabilities_count: int = 0
    medium_vulnerabilities_count: int = 0
    low_vulnerabilities_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Converts the report into a serializable dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'network_ranges': json.dumps(self.network_ranges),
            'scan_parameters': json.dumps(self.scan_parameters),
            'total_devices': self.total_devices,
            'total_open_ports': self.total_open_ports,
            'total_vulnerabilities': self.total_vulnerabilities
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NetworkScan':
        """Create a report from a dictionary."""
        if 'start_time' in data and isinstance(data['start_time'], str):
            data['start_time'] = datetime.datetime.fromisoformat(data['start_time'])
        if 'end_time' in data and isinstance(data['end_time'], str):
            data['end_time'] = datetime.datetime.fromisoformat(data['end_time'])

        if isinstance(data.get('network_ranges'), str):
            data['network_ranges'] = json.loads(data['network_ranges'])
        if isinstance(data.get('scan_parameters'), str):
            data['scan_parameters'] = json.loads(data['scan_parameters'])

        return cls(**data)

@dataclass
class NetworkDevice:
    """
    Represents a device discovered during a network scan.

    Contains detailed information about a single device,
    including services, configurations, and metadata.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""  # ID della scansione in cui è stato rilevato
    ip: str = ""
    mac: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    services: List[Dict[str, Any]] = field(default_factory=list)
    is_alive: bool = False
    reachable_protocols: List[str] = field(default_factory=list)
    potential_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    closed_ports: List[int] = field(default_factory=list)
    filtered_ports: List[int] = field(default_factory=list)
    additional_info: Dict[str, Any] = field(default_factory=dict)
    first_seen: datetime = field(default_factory=datetime.datetime.now)
    last_seen: datetime = field(default_factory=datetime.datetime.now)

    # Informazioni di rete aggiuntive
    subnet: Optional[str] = None  # Subnet del dispositivo
    default_gateway: Optional[str] = None  # Gateway predefinito
    dns_servers: List[str] = field(default_factory=list)  # Server DNS

    # Dettagli di configurazione di rete
    network_interfaces: List[Dict[str, Any]] = field(default_factory=list)
    # Esempio di struttura:
    # [
    #     {
    #         'name': 'eth0',
    #         'ip': '192.168.1.100',
    #         'mac': '00:11:22:33:44:55',
    #         'type': 'ethernet',
    #         'status': 'up'
    #     }
    # ]

    # Informazioni sul traffico di rete
    traffic_profile: Dict[str, Any] = field(default_factory=dict)
    # Esempio:
    # {
    #     'total_bytes_sent': 1024000,
    #     'total_bytes_received': 2048000,
    #     'active_connections': 10,
    #     'most_used_ports': [80, 443, 22]
    # }

    # Classificazione del dispositivo
    device_type: Optional[str] = None  # server, workstation, iot, network_device
    device_role: Optional[str] = None  # web_server, database, router, etc.

    def to_dict(self) -> Dict[str, Any]:
        """Converts the report into a serializable dictionary."""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'ip': self.ip,
            'mac': self.mac,
            'hostname': self.hostname,
            'os': self.os,
            'os_version': self.os_version,
            'services': json.dumps(self.services),
            'is_alive': self.is_alive,
            'reachable_protocols': json.dumps(self.reachable_protocols),
            'potential_vulnerabilities': json.dumps(self.potential_vulnerabilities),
            'open_ports': json.dumps(self.open_ports),
            'closed_ports': json.dumps(self.closed_ports),
            'filtered_ports': json.dumps(self.filtered_ports),
            'additional_info': json.dumps(self.additional_info),
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NetworkDevice':
        """Create a report from a dictionary."""
        if 'first_seen' in data and isinstance(data['first_seen'], str):
            data['first_seen'] = datetime.datetime.fromisoformat(data['first_seen'])
        if 'last_seen' in data and isinstance(data['last_seen'], str):
            data['last_seen'] = datetime.datetime.fromisoformat(data['last_seen'])

        deserialize_fields = [
            'services', 'reachable_protocols',
            'potential_vulnerabilities', 'open_ports',
            'closed_ports', 'filtered_ports', 'additional_info'
        ]

        for field_name in deserialize_fields:
            if field_name in data and isinstance(data[field_name], str):
                try:
                    data[field_name] = json.loads(data[field_name])
                except (json.JSONDecodeError, TypeError):
                    # If deserialization fails, use the original value
                    pass

        return cls(**data)

    def update_from_scan_result(self, scan_result: Dict[str, Any]):
        """
        Updates the NetworkDevice object with the results of a scan.
        Args:
            scan_result: Dictionary containing the scan results
        """
        self.ip = scan_result.get('ip', self.ip)
        self.mac = scan_result.get('mac', self.mac)
        self.hostname = scan_result.get('hostname', self.hostname)

        os_details = scan_result.get('os_details', {})
        self.os = os_details.get('name', self.os)
        self.os_version = os_details.get('version', self.os_version)

        if 'services' in scan_result:
            existing_services = {
                (s.get('port'), s.get('service')) for s in self.services
            }
            for service in scan_result['services']:
                service_key = (service.get('port'), service.get('service'))
                if service_key not in existing_services:
                    self.services.append(service)
                    existing_services.add(service_key)

        port_types = ['open_ports', 'closed_ports', 'filtered_ports']
        for port_type in port_types:
            ports = scan_result.get(port_type, [])
            existing_ports = getattr(self, port_type)
            for port in ports:
                if port not in existing_ports:
                    existing_ports.append(port)

        if 'potential_vulnerabilities' in scan_result:
            existing_vulns = {
                (v.get('port'), v.get('service'))
                for v in self.potential_vulnerabilities
            }
            for vuln in scan_result.get('potential_vulnerabilities', []):
                vuln_key = (vuln.get('port'), vuln.get('service'))
                if vuln_key not in existing_vulns:
                    self.potential_vulnerabilities.append(vuln)
                    existing_vulns.add(vuln_key)

        self.last_seen = datetime.datetime.now()

        self.additional_info.update(scan_result.get('additional_info', {}))
