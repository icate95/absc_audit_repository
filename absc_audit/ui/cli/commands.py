import typer
import logging
from typing import Optional
from rich.console import Console
from rich.table import Table

from absc_audit.core.engine import AuditEngine
from absc_audit.storage.sqlite import SQLiteStorage
from absc_audit.config.settings import Settings
from absc_audit.storage.models import Target, AuditCheck

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

        targets = storage.targets()

        if not targets:
            console.print("[yellow]No targets found.[/yellow]")
            return

        table = Table(title="Registered Targets")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="magenta")
        table.add_column("Hostname", style="green")
        table.add_column("OS", style="blue")
        table.add_column("Group", style="yellow")

        for target in targets:
            table.add_row(
                str(target.id),
                target.name,
                target.hostname,
                target.os,
                target.group or "N/A"
            )

        console.print(table)
    except Exception as e:
        logger.error(f"Error listing targets: {e}")
        console.print(f"[red]Error: {e}[/red]")


@app.command()
def list_checks(
        category: Optional[str] = typer.Option(None, help="Filter checks by category"),
        priority: Optional[int] = typer.Option(None, help="Filter checks by priority")
):
    """List available security checks."""
    try:
        engine = AuditEngine()
        checks = engine.get_available_checks()

        filtered_checks = {}
        for check_id, check_class in checks.items():
            check_instance = check_class()

            # Apply filters
            if category and category.lower() not in check_instance.CATEGORY.lower():
                continue
            if priority is not None and check_instance.PRIORITY != priority:
                continue

            filtered_checks[check_id] = check_instance

        if not filtered_checks:
            console.print("[yellow]No checks found matching the criteria.[/yellow]")
            return

        table = Table(title="Available Security Checks")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="magenta")
        table.add_column("Category", style="green")
        table.add_column("Priority", style="blue")

        for check_id, check_instance in filtered_checks.items():
            table.add_row(
                check_id,
                check_instance.NAME,
                check_instance.CATEGORY,
                str(check_instance.PRIORITY)
            )

        console.print(table)
    except Exception as e:
        logger.error(f"Error listing checks: {e}")
        console.print(f"[red]Error: {e}[/red]")


def main():
    """Main entry point for the CLI application."""
    app()


if __name__ == "__main__":
    main()