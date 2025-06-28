"""
Configurazione e utility per i controlli di rete nel sistema di audit ABSC.

Questo modulo fornisce meccanismi per configurare e gestire
i controlli di rete in modo flessibile.
"""

from typing import Dict, Any, Optional, List
import ipaddress
import logging


class NetworkCheckConfiguration:
    """
    Gestore della configurazione per controlli di rete.

    Fornisce metodi per validare e gestire configurazioni di rete
    per i diversi tipi di controlli.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Inizializza la configurazione dei controlli di rete.

        Args:
            logger: Logger personalizzato (opzionale)
        """
        self.logger = logger or logging.getLogger('absc_audit.network_config')

    def validate_network_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Valida una configurazione di rete.

        Args:
            config: Dizionario di configurazione di rete

        Returns:
            Configurazione validata o sollevata un'eccezione
        """
        # Validazione range di rete
        network_range = config.get('network_range')
        if not network_range:
            raise ValueError("Network range è obbligatorio")

        try:
            ipaddress.ip_network(network_range, strict=False)
        except ValueError:
            raise ValueError(f"Range di rete non valido: {network_range}")

        # Validazione parametri opzionali
        config['scan_method'] = config.get('scan_method', 'nmap')
        valid_methods = ['nmap', 'scapy']
        if config['scan_method'] not in valid_methods:
            raise ValueError(f"Metodo di scansione non valido. Scegliere tra {valid_methods}")

        # Porte da scansionare
        config['ports'] = config.get('ports', '22,80,443,3389')

        # Timeout e impostazioni aggiuntive
        config['timeout'] = config.get('timeout', 5)
        config['max_threads'] = config.get('max_threads', 10)

        return config

    def generate_default_network_config(self,
                                        network_range: Optional[str] = None,
                                        scan_method: str = 'nmap') -> Dict[str, Any]:
        """
        Genera una configurazione di rete predefinita.

        Args:
            network_range: Range di rete (opzionale)
            scan_method: Metodo di scansione

        Returns:
            Configurazione di rete predefinita
        """
        default_config = {
            'network_range': network_range or '192.168.1.0/24',
            'scan_method': scan_method,
            'ports': '22,80,443,3389',
            'timeout': 5,
            'max_threads': 10
        }

        try:
            return self.validate_network_config(default_config)
        except ValueError as e:
            self.logger.error(f"Errore nella configurazione predefinita: {e}")
            raise

    def get_network_security_recommendations(self,
                                             scan_results: Dict[str, Any]) -> List[str]:
        """
        Genera raccomandazioni di sicurezza basate sui risultati della scansione.

        Args:
            scan_results: Risultati della scansione di rete

        Returns:
            Lista di raccomandazioni di sicurezza
        """
        recommendations = []

        # Analisi delle vulnerabilità
        vulnerabilities = scan_results.get('potential_vulnerabilities', [])
        for vuln in vulnerabilities:
            recommendations.append(
                f"Chiudere/Configurare la porta {vuln.get('port')} sul dispositivo {vuln.get('device')}"
            )

        # Analisi delle porte aperte
        open_ports = scan_results.get('open_ports', {})
        if len(open_ports) > 3:
            recommendations.append(
                f"Troppo molte porte aperte ({len(open_ports)}). Rivedere la configurazione del firewall."
            )

        # Raccomandazioni generali
        if not recommendations:
            recommendations.append("Nessuna vulnerabilità immediata rilevata. Continuare il monitoraggio.")

        return recommendations