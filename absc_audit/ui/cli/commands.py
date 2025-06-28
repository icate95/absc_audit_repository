import typer
import logging
from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
import uuid
import datetime

from absc_audit.core.engine import AuditEngine
from absc_audit.checks.base import BaseCheck
from absc_audit.checks.checkRegistry import CheckRegistry
from absc_audit.storage.sqlite import SQLiteStorage
from absc_audit.config.settings import Settings
from absc_audit.storage.models import Target, AuditCheck, NetworkScan, NetworkDevice

from absc_audit.network.scanner import NetworkScanner
from absc_audit.network.config import NetworkCheckConfiguration
from absc_audit.network.dependencies import initialize_network_dependencies

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create Typer app
app = typer.Typer(help="ABSC Audit System CLI - Automated Security Audit Tool")
console = Console()


@app.command()
def add_target(
        name: str = typer.Option(..., help="Target name"),
        hostname: str = typer.Option(..., help="Hostname or IP address"),
        os: str = typer.Option(..., help="Operating system (linux/windows/macos)"),
        description: Optional[str] = typer.Option(None, help="Target description"),
        group: Optional[str] = typer.Option(None, help="Target group"),
        tags: Optional[str] = typer.Option(None, help="Comma-separated tags")
):
    """Add a new target to the audit system."""
    try:
        settings = Settings()
        storage = SQLiteStorage(settings)

        # Convert tags to list
        tags_list = tags.split(',') if tags else []

        target = Target(
            name=name,
            hostname=hostname,
            os=os,
            description=description or "",
            group=group or "",
            tags=tags_list
        )

        storage.save_target(target)
        console.print(f"[green]Target '{name}' added successfully![/green]")
    except Exception as e:
        logger.error(f"Error adding target: {e}")
        console.print(f"[red]Error: {e}[/red]")


@app.command()
def list_targets():
    """List all registered targets."""
    try:
        settings = Settings()
        storage = SQLiteStorage(settings)

        targets = storage.get_all_targets()

        if not targets:
            console.print("[yellow]No targets found.[/yellow]")
            return

        table = Table(title="Registered Targets")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="magenta")
        table.add_column("Hostname", style="green")
        table.add_column("IP Address", style="green")
        table.add_column("Os Type", style="green")
        table.add_column("Os Version", style="green")
        table.add_column("Description", style="green")
        table.add_column("Group", style="yellow")

        for target in targets:
            table.add_row(
                str(target.id),
                target.name,
                target.hostname,
                target.ip_address,
                target.os_type,
                target.os_version,
                target.description,
                target.group or "N/A",
            )

        console.print(table)
    except Exception as e:
        logger.error(f"Error listing targets: {e}")
        console.print(f"[red]Error: {e}[/red]")


@app.command()
def add_check(
        ctx: typer.Context,
        interactive: bool = typer.Option(True, help="Interactive check creation")
):
    """
    Adds a new security check to the system.

    Supports interactive and non-interactive mode.
    """
    try:
        settings = Settings()
        storage = SQLiteStorage(settings)
        check_registry = CheckRegistry()

        if interactive:
            name = Prompt.ask("Name of the control", default="")
            while not name:
                console.print("[red]Name is required.[/red]")
                name = Prompt.ask("Name of the control", default="")

            description = Prompt.ask("Description of the control", default="")

            question = Prompt.ask("Verification question", default="")

            possible_answers = []
            while True:
                answer = Prompt.ask("Add a possible answer (leave blank to finish)", default="")
                if not answer:
                    break
                possible_answers.append(answer)

            console.print("\nCategories available:")
            for i, category in enumerate(CheckRegistry.CATEGORIES, 1):
                console.print(f"{i}. {category}")

            while True:
                category_choice = Prompt.ask("Select category (number)", default="")
                try:
                    category_index = int(category_choice) - 1
                    if 0 <= category_index < len(CheckRegistry.CATEGORIES):
                        category = CheckRegistry.CATEGORIES[category_index]
                        break
                    else:
                        console.print("[red]Invalid category.[/red]")
                except ValueError:
                    console.print("[red]Please enter a valid number.[/red]")

            while True:
                priority_str = Prompt.ask("Priority (1-High, 2-Medium, 3-Low)", default="2")
                try:
                    priority = int(priority_str)
                    if check_registry.validate_priority(priority):
                        break
                    else:
                        console.print("[red]Priority must be 1, 2 or 3.[/red]")
                except ValueError:
                    console.print("[red]Please enter a valid number.[/red]")

            params = {}
            while Confirm.ask("Want to add custom parameters?"):
                param_name = Prompt.ask("Parameter name")
                param_value = Prompt.ask("Parameter value")
                params[param_name] = param_value

            console.print("\n[bold]Control Summary:[/bold]")
            console.print(f"Name: {name}")
            console.print(f"Description: {description}")
            console.print(f"Question: {question}")
            console.print(f"Possible responses: {possible_answers}")
            console.print(f"Category: {category}")
            console.print(f"Priority: {priority}")
            console.print(f"Params: {params}")

            if not Confirm.ask("Do you confirm the insertion?"):
                console.print("[yellow]Entry cancelled.[/yellow]")
                return

        else:
            console.print("[red]Non-interactive mode not yet supported.[/red]")
            return

        # Genera un ID univoco per il controllo
        # Formato: categoria.sottocategoria.progressivo
        # Es: "1.1.1" per il primo controllo di inventario
        last_checks = check_registry.get_checks_by_category(category[:1])
        if last_checks:
            last_id = max(last_checks.keys())
            parts = last_id.split('.')
            new_id = f"{parts[0]}.{parts[1]}.{int(parts[2]) + 1}"
        else:
            new_id = f"{category[:1]}.1.1"

        class DynamicCheck(BaseCheck):
            ID = new_id
            NAME = name
            DESCRIPTION = description
            QUESTION = question
            POSSIBLE_ANSWERS = possible_answers
            CATEGORY = category
            PRIORITY = priority
            PARAMS = params

            def run(self, target, params=None):
                result = self.prepare_result()
                result['status'] = 'NOT_IMPLEMENTED'
                result['details'] = {
                    'message': 'This is a dynamic control, specific implementation is required.'
                }
                return result

        audit_check = AuditCheck(
            id=new_id,
            name=name,
            description=description,
            question=question,
            possible_answers=possible_answers,
            category=category,
            priority=priority,
            params=params
        )

        storage.save_check(audit_check)
        check_registry.register(new_id, DynamicCheck)

        console.print(f"[green]Control '{name}' successfully added with ID: {new_id}[/green]")

    except Exception as e:
        logger.error(f"Error adding control: {e}")
        console.print(f"[red]Errore: {e}[/red]")


@app.command()
def list_checks(
        category: Optional[str] = typer.Option(None, help="Filter checks by categories"),
        priority: Optional[int] = typer.Option(None, help="Filter checks by priority")
):
    """
   Lists all available security controls.

    If no filters are specified, shows all controls.
    """
    try:
        settings = Settings()
        storage = SQLiteStorage(settings)

        categories = get_categories()
        category_map = {cat['name'].lower(): cat['id'] for cat in categories}

        category_id = None
        if category:
            category_lower = category.lower()
            matching_categories = [
                cat_id for cat_name, cat_id in category_map.items()
                if category_lower in cat_name.lower()
            ]

            if not matching_categories:
                console.print(f"[yellow]No categories found for '{category}'.[/yellow]")
                return

            category_id = matching_categories[0]

        all_checks = storage.get_all_checks(category_id)

        filtered_checks = [
            check for check in all_checks
            if (priority is None or check.priority == priority)
        ]

        if not filtered_checks:
            console.print("[yellow]No controls found with the specified criteria.[/yellow]")
            return

        table = Table(title="Security Checks Available")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="magenta")
        table.add_column("Category", style="green")
        table.add_column("Priority", style="blue")
        table.add_column("Description", style="yellow")

        for check in sorted(filtered_checks, key=lambda x: x.id):
            category_name = check.category.get('name', 'N/A') if isinstance(check.category, dict) else 'N/A'

            table.add_row(
                check.id,
                check.name,
                category_name,
                str(check.priority),
                check.description or "No description",
            )

        console.print(table)

    except Exception as e:
        logger.error(f"Error listing controls: {e}")
        console.print(f"[red]Error: {e}[/red]")

def get_categories():
    return []


@app.command()
def network_scan(
    interactive: bool = typer.Option(True, help="Interactive network scanning mode"),
    detailed: bool = typer.Option(False, help="Perform detailed network scan")
):
    """
    Performs a full network scan and analyzes detected devices.
    """
    try:
        dep_manager = initialize_network_dependencies(logger)

        missing_deps = dep_manager.install_missing_dependencies()
        console.print("[blue]Dendency status:[/blue]")
        for lib, installed in missing_deps.items():
            status = "[green]Installed[/green]" if installed else "[red]Not installed[/red]"
            console.print(f"- {lib}: {status}")

        network_config = NetworkCheckConfiguration(logger)
        network_scanner = NetworkScanner(logger)

        settings = Settings()
        storage = SQLiteStorage(settings)

        network_ranges = []
        scan_params = {}

        if interactive:
            scan_name = Prompt.ask("Network scan name", default="Network Scan")
            scan_description = Prompt.ask("Description (optional)", default="")

            while True:
                network_range = Prompt.ask("Enter a network range (CIDR, e.g. 192.168.1.0/24)", default="")
                if not network_range:
                    break

                try:
                    network_config.validate_network_config({'network_range': network_range})
                    network_ranges.append(network_range)
                except ValueError as e:
                    console.print(f"[red]Errore: {e}[/red]")

            scan_methods = ['nmap', 'scapy']
            scan_method = Prompt.ask(
                "Select the scanning method",
                choices=scan_methods,
                default="nmap"
            )

            default_ports = '22,80,443,3389'
            ports = Prompt.ask("Ports to scan (comma separated)", default=default_ports)

            detailed = Confirm.ask("Perform detailed scan?", default=False)
            save_targets = Confirm.ask("Save devices as targets?", default=False)

            scan_params = {
                'scan_method': scan_method,
                'ports': ports,
                'detailed': detailed
            }
        else:
            scan_name = "Network Scan Automatico"
            scan_description = "Automatic network scan"
            network_ranges = ["192.168.1.0/24"]
            scan_params = {
                'scan_method': 'nmap',
                'ports': '22,80,443,3389',
                'detailed': False
            }

        scan_id = str(uuid.uuid4())

        network_scan = NetworkScan(
            id=scan_id,
            name=scan_name,
            description=scan_description,
            start_time=datetime.datetime.now(),
            network_ranges=network_ranges,
            scan_parameters=scan_params
        )
        storage.save_network_scan(network_scan)

        all_devices = []

        console.print(f"\n[bold]Start Network Scan - ID: {scan_id}[/bold]")
        for network_range in network_ranges:
            console.print(f"\n[cyan]Range Scan: {network_range}[/cyan]")

            try:
                if scan_params['scan_method'] == 'scapy':
                    devices = network_scanner.scan_network_scapy(network_range)
                else:
                    scan_type = 'vulnerability' if scan_params['detailed'] else 'basic'
                    devices = network_scanner.scan_network_nmap(
                        network_range,
                        ports=scan_params['ports'],
                        scan_type=scan_type
                    )

                logger.info(f"Scanning {network_range} completed")
                logger.info(f"Devices detected: {len(devices)}")

                for device in devices:
                    logger.info(f"Device detected:")
                    logger.info(f"  IP: {device.get('ip', 'N/A')}")
                    logger.info(f"  MAC: {device.get('mac', 'N/A')}")
                    logger.info(f"  Hostname: {device.get('hostname', 'N/A')}")

                    if 'services' in device:
                        logger.info("  Servizi:")
                        for service in device.get('services', []):
                            logger.info(
                                f"    - Porta {service.get('port')}: "
                                f"{service.get('service')} "
                                f"({service.get('state')}) "
                                f"Versione: {service.get('version', 'N/A')}"
                            )

                network_devices = []
                for device in devices:
                    network_device = NetworkDevice(
                        scan_id=scan_id,
                        ip=device.get('ip', ''),
                        mac=device.get('mac', ''),
                        hostname=device.get('hostname', ''),
                        os=device.get('os_details', {}).get('name', ''),
                        services=device.get('services', []),
                        additional_info=device
                    )
                    network_devices.append(network_device)

                storage.save_network_devices(network_devices)

                all_devices.extend(devices)

            except Exception as e:
                logger.error(f"Error while scanning {network_range}: {e}")

        security_assessment = network_scanner.network_security_assessment(
            ','.join(network_ranges)
        )

        console.print("\n[bold]Scan Summary:[/bold]")
        console.print(f"ID Scan: {scan_id}")
        console.print(f"Name: {scan_name}")
        console.print(f"Descriptin: {scan_description}")
        console.print(f"Ranges scanned: {', '.join(network_ranges)}")
        console.print(f"Devices Detected: {len(all_devices)}")

        if Confirm.ask("View full device details?"):
            for device in all_devices:
                console.print("\n[cyan]Device Details:[/cyan]")
                for key, value in device.items():
                    console.print(f"{key}: {value}")

        if interactive and save_targets:
            console.print("\n[bold]Saving devices as targets:[/bold]")
            saved_count = 0
            for device in all_devices:
                try:
                    target = Target(
                        name=device.get('hostname', device.get('ip', 'Unknown')),
                        hostname=device.get('ip', ''),
                        os_type=device.get('os_details', {}).get('name', 'Unknown'),
                        description=f"Device detected during network scan (ID: {scan_id})"
                    )
                    storage.save_target(target)
                    saved_count += 1
                except Exception as e:
                    logger.error(f"Error saving target: {e}")

            console.print(f"[blue]Total targets saved: {saved_count}[/blue]")

        network_scan.end_time = datetime.datetime.now()
        network_scan.total_devices = len(all_devices)
        storage.update_network_scan(network_scan)

        recommendations = network_config.get_network_security_recommendations(security_assessment)
        console.print("\n[bold]Security Recommendations:[/bold]")
        for rec in recommendations:
            console.print(f"- {rec}")

    except Exception as e:
        logger.error(f"Error while scanning network: {e}")
        console.print(f"[red]Error: {e}[/red]")


@app.command()
def network_assessment(
        network_range: str = typer.Option("192.168.0.0/24", help="Network range to assess"),
        detailed: bool = typer.Option(False, help="Perform detailed security assessment")
):
    """
    Performs an in-depth network security assessment.
    """
    try:
        dep_manager = initialize_network_dependencies(logger)

        missing_deps = dep_manager.install_missing_dependencies()
        console.print("[blue]State Dependencies:[/blue]")
        for lib, installed in missing_deps.items():
            status = "[green]Installed[/green]" if installed else "[red]Not installed[/red]"
            console.print(f"- {lib}: {status}")

        settings = Settings()
        storage = SQLiteStorage(settings)

        network_config = NetworkCheckConfiguration(logger)
        network_scanner = NetworkScanner(logger)

        console.print(f"\n[bold]Assessment di Sicurezza per la Rete {network_range}[/bold]")

        if detailed:
            devices = network_scanner.scan_network_nmap(network_range, scan_type='vulnerability')
        else:
            devices = network_scanner.scan_network_nmap(network_range)

        network_analysis = enrich_network_data( devices)
        security_assessment = network_scanner.network_security_assessment(network_range)

        try:
            network_scan = NetworkScan(
                name=f"Network Assessment {network_range}",
                description=f"Valutazione di sicurezza per il range {network_range}",
                network_ranges=[network_range],
                scan_parameters={
                    'detailed': detailed,
                    'type': 'assessment'
                },
                total_devices=len(devices),
                total_open_ports=len(security_assessment.get('open_ports_summary', {})),
                total_vulnerabilities=len(security_assessment.get('potential_vulnerabilities', [])),
                total_subnets=len(network_analysis['subnets']),
                network_topology={
                    'subnets': network_analysis['subnets'],
                    'device_types': network_analysis['device_types']
                },
                network_protocols=network_analysis['protocols'],
                network_services_summary=network_analysis['services_summary'],
                critical_vulnerabilities_count=network_analysis['vulnerabilities']['critical'],
                medium_vulnerabilities_count=network_analysis['vulnerabilities']['medium'],
                low_vulnerabilities_count=network_analysis['vulnerabilities']['low']

            )

            storage.save_network_scan(network_scan)

            network_devices = []
            for device in devices:
                network_device = NetworkDevice(
                    scan_id=network_scan.id,
                    ip=device.get('ip', ''),
                    mac=device.get('mac', ''),
                    hostname=device.get('hostname', ''),
                    os=device.get('os_details', {}).get('name', ''),
                    services=device.get('services', []),
                    additional_info=device,
                    subnet=str(ipaddress.ip_network(device.get('ip', '') + '/24', strict=False)) if device.get(
                        'ip') else None,
                    device_type=_classify_device_type(device),
                    device_role=_determine_device_role(device),
                    network_interfaces=_extract_network_interfaces(device),
                    traffic_profile=_analyze_device_traffic(device)
                )
                network_devices.append(network_device)

            storage.save_network_devices(network_devices)

        except Exception as storage_error:
            logger.error(f"Error saving scan data: {storage_error}")
            console.print(f"[yellow]Warning: Unable to save scan data: {storage_error}[/yellow]")

        console.print("\n[bold]Recommended Safety Checks:[/bold]")

        # todo use actual controls
        suggested_checks = [
            {
                'id': '1.1.1',
                'name': 'Inventario Dispositivi',
                'description': 'Verificare e documentare tutti i dispositivi di rete',
                'rationale': 'Sono stati rilevati {} dispositivi che necessitano di un inventario completo'.format(
                    len(devices)
                )
            },
            {
                'id': '2.1.1',
                'name': 'Gestione Accessi',
                'description': 'Verifica delle porte aperte e delle configurazioni di accesso',
                'rationale': 'Sono state rilevate {} porte aperte che potrebbero rappresentare rischi di sicurezza'.format(
                    len(security_assessment.get('open_ports_summary', {}))
                )
            },
            {
                'id': '4.1.1',
                'name': 'Rilevamento Vulnerabilità',
                'description': 'Identificazione e valutazione delle vulnerabilità di rete',
                'rationale': 'Sono state identificate {} potenziali vulnerabilità'.format(
                    len(security_assessment.get('potential_vulnerabilities', []))
                )
            },
            {
                'id': '8.1.1',
                'name': 'Protezione Endpoint',
                'description': 'Verifica delle configurazioni di sicurezza degli endpoint',
                'rationale': 'Necessario verificare le configurazioni di sicurezza dei {} dispositivi rilevati'.format(
                    len(devices)
                )
            }
        ]

        for check in suggested_checks:
            console.print(f"\n[cyan]Controllo {check['id']}: {check['name']}[/cyan]")
            console.print(f"Descrizione: {check['description']}")
            console.print(f"Razionale: {check['rationale']}")

        recommendations = network_config.get_network_security_recommendations(security_assessment)
        console.print("\n[bold]Raccomandazioni di Sicurezza:[/bold]")
        for rec in recommendations:
            console.print(f"- {rec}")

    except Exception as e:
        logger.error(f"Errore durante l'assessment di rete: {e}")
        console.print(f"[red]Errore: {e}[/red]")

def enrich_network_data(devices: List[Dict]) -> Dict[str, Any]:
    """
    Enrich network information with advanced analysis.

    Args:
        devices: Detected devices

    Returns:
        Dictionary with advanced network information
    """
    network_analysis = {
        'subnets': set(),
        'protocols': set(),
        'services_summary': {},
        'device_types': {},
        'vulnerabilities': {
            'critical': 0,
            'medium': 0,
            'low': 0
        }
    }

    for device in devices:
        if device.get('ip'):
            subnet = ipaddress.ip_network(device['ip'] + '/24', strict=False)
            network_analysis['subnets'].add(str(subnet))

        for service in device.get('services', []):
            service_name = service.get('service', 'Unknown')
            network_analysis['services_summary'][service_name] = (
                    network_analysis['services_summary'].get(service_name, 0) + 1
            )

            network_analysis['protocols'].add(service.get('protocol', 'Unknown'))

        os = device.get('os_details', {}).get('name', 'Unknown')
        network_analysis['device_types'][os] = (
                network_analysis['device_types'].get(os, 0) + 1
        )

        vulnerabilities = device.get('potential_vulnerabilities', [])
        for vuln in vulnerabilities:
            risk_level = vuln.get('risk_level', 'low').lower()
            if risk_level == 'critical':
                network_analysis['vulnerabilities']['critical'] += 1
            elif risk_level == 'medium':
                network_analysis['vulnerabilities']['medium'] += 1
            else:
                network_analysis['vulnerabilities']['low'] += 1

    network_analysis['subnets'] = list(network_analysis['subnets'])
    network_analysis['protocols'] = list(network_analysis['protocols'])

    return network_analysis

def _classify_device_type(device: Dict) -> str:
    """
    Classify the device type based on the available information.
    """
    os = device.get('os_details', {}).get('name', '').lower()
    services = [s.get('service', '').lower() for s in device.get('services', [])]

    if 'windows server' in os or 'linux' in os:
        if any('database' in s for s in services):
            return 'database_server'
        if any('web' in s for s in services):
            return 'web_server'
        return 'server'

    if 'windows' in os or 'macos' in os:
        return 'workstation'

    if any('printer' in s for s in services):
        return 'printer'

    if any('router' in s or 'switch' in s for s in services):
        return 'network_device'

    return 'unknown'

def _determine_device_role(device: Dict) -> str:
    """
    Determines the specific role of the device.
    """
    services = device.get('services', [])
    roles = []

    for service in services:
        service_name = service.get('service', '').lower()
        if 'http' in service_name:
            roles.append('web')
        if 'sql' in service_name:
            roles.append('database')
        if 'ssh' in service_name:
            roles.append('admin')

    return ','.join(roles) if roles else 'generic'

def _extract_network_interfaces(device: Dict) -> List[Dict]:
    """
    Extracts information about network interfaces.
    """
    return [{
        'name': 'primary',
        'ip': device.get('ip', ''),
        'mac': device.get('mac', ''),
        'type': 'ethernet',
        'status': 'up'
    }]

def _analyze_device_traffic(device: Dict) -> Dict:
    """
    Analyze the device's traffic profile.
    """
    return {
        'active_connections': len(device.get('services', [])),
        'open_ports': [s.get('port') for s in device.get('services', [])]
    }
def main():
    """Main entry point for the CLI application."""
    app()


if __name__ == "__main__":
    main()