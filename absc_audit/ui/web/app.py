"""
Web Application - Web application for the ABSC audit system.

This module implements the Flask web application for the audit system.
"""
import logging
import os
import json
from datetime import datetime
import socket
import uuid

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from absc_audit.config.settings import Settings
from absc_audit.core.engine import AuditEngine, CheckRegistry
from absc_audit.core.result_manager import ResultManager
from absc_audit.core.scheduler import Scheduler
from absc_audit.network.scanner import NetworkScanner
from absc_audit.storage.sqlite import SQLiteStorage
from absc_audit.ui.web.forms import (
    LoginForm, RegisterForm, TargetForm, ScheduledAuditForm,
    UserForm, ProfileForm, ReportForm, NetworkScanForm
)

from absc_audit.network.config import NetworkCheckConfiguration
from absc_audit.network.dependencies import initialize_network_dependencies

from absc_audit.ui.web.models import User
from absc_audit.storage.models import Target, AuditCheck, ScheduledAudit, NetworkScan, NetworkDevice
from absc_audit.ui.web.utils import init_registry

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "development-key")
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."

settings = Settings()
storage = SQLiteStorage(settings)
result_manager = ResultManager(settings)
result_manager.configure_storage(storage)
engine = AuditEngine(settings)
engine.register_result_manager(result_manager)
scheduler = Scheduler(engine, storage, settings)

init_registry(engine, storage)

if os.environ.get("ENABLE_SCHEDULER", "false").lower() == "true":
    scheduler.start()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@login_manager.user_loader
def load_user(user_id):
    """Load a user from the database"""
    user_account = storage.get_user(user_id)
    if user_account:
        return User.from_user_account(user_account)
    return None

@app.route("/login", methods=["GET", "POST"])
def login():
    """Manages user login."""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        users = storage.get_users_by_username(username)
        if not users:
            flash("Invalid username or password", "danger")
            return render_template("login.html", form=form)

        user_account = users[0]
        if check_password_hash(user_account.password_hash, password):
            user_account.last_login = datetime.now()
            storage.save_user(user_account)

            user = User.from_user_account(user_account)
            login_user(user)

            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))
        else:
            flash("Invalid username or password", "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    """Manages user logout."""
    logout_user()
    flash("You have successfully logged out", "success")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Manages the registration of new users."""
    is_first_user = len(storage.get_all_users()) == 0

    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        existing_users = storage.get_users_by_username(username)
        if existing_users:
            flash("Username already in use", "danger")
            return render_template("register.html", form=form, is_first_user=is_first_user)

        from absc_audit.storage.models import UserAccount
        user_account = UserAccount(
            username=username,
            password_hash=generate_password_hash(password),
            email=email,
            first_name=first_name,
            last_name=last_name,
            role="admin" if is_first_user else "user"
        )

        try:
            storage.save_user(user_account)
            flash("Registration completed successfully. You can log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"Error while registering: {str(e)}", "danger")

    return render_template("register.html", form=form, is_first_user=is_first_user)


@app.route("/")
@login_required
def dashboard():
    """Show the main dashboard."""
    targets_count = len(storage.get_all_targets())
    latest_results = storage.get_latest_results()

    total_checks = len(latest_results)
    compliant = sum(1 for r in latest_results if r.score >= settings.compliance_threshold)
    compliance_rate = (compliant / total_checks * 100) if total_checks > 0 else 0

    recent_audits = []
    for result in sorted(latest_results, key=lambda r: r.timestamp, reverse=True)[:5]:
        target = storage.get_target(result.target_id)
        recent_audits.append({
            "id": result.id,
            "check_id": result.check_id,
            "target_name": target.name if target else "Target sconosciuto",
            "timestamp": result.timestamp,
            "status": result.status,
            "score": result.score
        })

    return render_template(
        "dashboard.html",
        targets_count=targets_count,
        total_checks=total_checks,
        compliant=compliant,
        compliance_rate=compliance_rate,
        recent_audits=recent_audits
    )


@app.route("/targets")
@login_required
def targets_list():
    """Show target list."""
    targets = storage.get_all_targets()

    checks = storage.get_all_checks()
    categories = {}
    for check in checks:
        if check.category not in categories:
            categories[check.category] = []
        categories[check.category].append(check)

    return render_template("targets/list.html", targets=targets, categories=categories)

@app.route("/targets/add", methods=["GET", "POST"])
@login_required
def target_add():
    """Add new target - Supports manual addition and network scan."""
    manual_form = TargetForm()

    network_scan_form = NetworkScanForm()

    if request.method == 'POST':
        form_type = request.form.get('form_type')

        if form_type == 'manual_add':
            if manual_form.validate_on_submit():
                target = Target(
                    name=manual_form.name.data,
                    hostname=manual_form.hostname.data,
                    ip_address=manual_form.ip_address.data,
                    os_type=manual_form.os_type.data,
                    os_version=manual_form.os_version.data,
                    description=manual_form.description.data,
                    group=manual_form.group.data,
                    tags=manual_form.tags.data.split(",") if manual_form.tags.data else []
                )

                try:
                    storage.save_target(target)
                    flash(f"Target '{target.name}' added successfully", "success")
                    return redirect(url_for("targets_list"))
                except Exception as e:
                    flash(f"Error adding target: {str(e)}", "danger")

        elif form_type == 'network_scan':
            if network_scan_form.validate_on_submit():
                try:
                    network_ranges = [
                        range.strip()
                        for range in network_scan_form.network_ranges.data.split(',')
                        if range.strip()
                    ]

                    scan_id = str(uuid.uuid4())

                    network_scan = NetworkScan(
                        id=scan_id,
                        name=network_scan_form.scan_name.data,
                        description=network_scan_form.description.data,
                        start_time=datetime.now(),
                        network_ranges=network_ranges,
                        scan_parameters={
                            'scan_method': network_scan_form.scan_method.data,
                            'ports': network_scan_form.ports.data,
                            'detailed': network_scan_form.detailed.data
                        }
                    )

                    storage.save_network_scan(network_scan)

                    network_scanner = NetworkScanner(logger)
                    all_devices = []

                    for network_range in network_ranges:
                        try:
                            if network_scan_form.scan_method.data == 'scapy':
                                devices = network_scanner.scan_network_scapy(network_range)
                            else:
                                scan_type = 'vulnerability' if network_scan_form.detailed.data else 'basic'
                                devices = network_scanner.scan_network_nmap(
                                    network_range,
                                    ports=network_scan_form.ports.data,
                                    scan_type=scan_type
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

                    network_scan.end_time = datetime.now()
                    network_scan.total_devices = len(all_devices)
                    storage.update_network_scan(network_scan)

                    if network_scan_form.save_targets.data:
                        saved_count = 0
                        for device in all_devices:
                            try:
                                target = Target(
                                    name=device.get('hostname', device.get('ip', 'Unknown')),
                                    hostname=device.get('ip', ''),
                                    ip_address=device.get('ip', ''),
                                    os_type=device.get('os_details', {}).get('name', 'Unknown'),
                                    description=f"Device detected during network scan (ID: {scan_id})"
                                )
                                storage.save_target(target)
                                saved_count += 1
                            except Exception as e:
                                logger.error(f"Error saving target: {e}")

                        flash(f"{saved_count} devices saved as targets", "success")

                    return render_template("targets/network_scan_results.html",
                                           devices=all_devices,
                                           scan_id=scan_id)

                except Exception as e:
                    flash(f"Error while scanning network: {str(e)}", "danger")

    return render_template("targets/form.html",
                           form=manual_form,
                           network_scan_form=network_scan_form,
                           title="Aggiungi Target")


@app.route("/targets/add_device", methods=["POST"])
@login_required
def add_device_as_target():
    """Adds a single device as a target."""
    device_data = request.form.get('device')

    try:
        device = json.loads(device_data)

        target = Target(
            name=device.get('hostname', device.get('ip', 'Unknown')),
            hostname=device.get('ip', ''),
            ip_address=device.get('ip', ''),
            os_type=device.get('os_details', {}).get('name', 'Unknown'),
            description="Device detected during network scan"
        )

        storage.save_target(target)

        flash(f"Device {target.name} added as target", "success")
    except Exception as e:
        flash(f"Error adding device: {str(e)}", "danger")

    return redirect(url_for("targets_list"))

@app.route("/targets/add_from_scan", methods=["POST"])
@login_required
def add_targets_from_scan():
    """Add selected targets from network scan."""
    data = request.get_json()
    selected_device_ids = data.get('selected_devices', [])

    logger.info(f"selected_device_ids: {selected_device_ids}")
    if not selected_device_ids:
        return jsonify({'success': False, 'message': 'No devices selected'}), 400

    try:
        discovered_devices = get_discovered_devices(selected_device_ids)

        added_targets = []
        for device in discovered_devices:
            target = Target(
                name=device.hostname or device.ip,
                hostname=device.hostname or '',
                ip_address=device.ip,
                os_type=device.os,
                os_version=device.os_version
            )

            storage.save_target(target)
            added_targets.append(target)

        return jsonify({
            'success': True,
            'message': f'{len(added_targets)} added devices',
            'targets': [t.to_dict() for t in added_targets]
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error adding devices: {str(e)}'
        }), 500


@app.route("/targets/perform_network_scan", methods=["POST"])
@login_required
def perform_network_scan_route():
    """Endpoint to perform network scanning with advanced implementation."""
    try:
        dep_manager = initialize_network_dependencies(logger)

        missing_deps = dep_manager.install_missing_dependencies()
        logger.info("State Dependencies:")
        for lib, installed in missing_deps.items():
            logger.info(f"- {lib}: {'Installed' if installed else 'Not installed'}")

        scan_name = request.form.get('scan_name', 'Network Scan')
        description = request.form.get('description', '')
        network_ranges = request.form.get('network_ranges', '192.168.1.0/24').split(',')
        scan_method = request.form.get('scan_method', 'nmap')
        ports = request.form.get('ports', '22,80,443,3389')
        detailed = request.form.get('detailed', 'vulnerability')

        network_config = NetworkCheckConfiguration(logger)
        network_scanner = NetworkScanner(logger)

        scan_id = str(uuid.uuid4())

        network_scan = NetworkScan(
            id=scan_id,
            name=scan_name,
            description=description,
            start_time=datetime.now(),
            network_ranges=network_ranges,
            scan_parameters={
                'scan_method': scan_method,
                'ports': ports,
                'detailed': detailed
            }
        )
        storage.save_network_scan(network_scan)

        all_devices = []
        network_devices = []

        for network_range in network_ranges:
            try:
                network_config.validate_network_config({'network_range': network_range})

                if scan_method == 'scapy':
                    devices = network_scanner.scan_network_scapy(network_range)
                else:
                    devices = network_scanner.scan_network_nmap(
                        network_range,
                        ports=ports,
                        scan_type=detailed
                    )

                logger.info(f"Scanning {network_range} completed")
                logger.info(f"Devices detected: {len(devices)}")

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

        network_scan.end_time = datetime.now()
        network_scan.total_devices = len(all_devices)
        storage.update_network_scan(network_scan)

        results = []
        existing_targets = storage.get_all_targets()

        for device in all_devices:
            exists = any(
                target.ip_address == device.get('ip') or
                (device.get('hostname') and target.hostname == device.get('hostname'))
                for target in existing_targets
            )

            result_device = {
                'id': str(uuid.uuid4()),
                'ip': device.get('ip', 'N/A'),
                'hostname': device.get('hostname', 'N/A'),
                'os': device.get('os_details', {}).get('name', 'Unknown'),
                'exists': exists,
                'services': device.get('services', []),
                'additional_details': device
            }
            results.append(result_device)

        return jsonify({
            'devices': results,
            'scan_id': scan_id
        })

    except Exception as e:
        logger.error(f"Error while scanning network: {e}", exc_info=True)
        return jsonify({
            'error': str(e)
        }), 500

def perform_network_scan(interface, network_range):
    """
    Performs network scanning using nmap or another library.

    Args:
        interface (str): Network interface to use
        network_range (str): Network range to scan

    Returns:
        List[NetworkDevice]: Discovered devices
    """
    try:
        import nmap

        nm = nmap.PortScanner()
        nm.scan(hosts=network_range, arguments='-sn')

        discovered_devices = []
        for host in nm.all_hosts():
            try:
                hostname = nm[host].hostname()

                # Cerca di identificare il sistema operativo
                os_match = nm[host].get('osmatch', [])
                os_name = os_match[0]['name'] if os_match else None

                device = NetworkDevice(
                    id=str(uuid.uuid4()),  # Genera un ID univoco
                    ip=host,
                    hostname=hostname,
                    os=os_name,
                    is_alive=nm[host]['status']['state'] == 'up'
                )

                discovered_devices.append(device)

            except Exception as host_error:
                # Log dell'errore per quel singolo host
                logger.warning(f"Error parsing host {host}: {host_error}")

        return discovered_devices

    except ImportError:
        # Fallback per sistemi senza nmap
        logger.error("Nmap library not installed. Use an alternate scanning method.")
        raise ImportError("Nmap library required for network scanning")


def get_network_interfaces():
    """
    Retrieves available network interfaces.

    Returns:
        List[str]: Network interface names
    """
    try:
        import psutil

        interfaces = [
            name for name, addrs in psutil.net_if_addrs().items()
            if any(
                addr.family == socket.AF_INET and
                not addr.address.startswith('127.') and
                not addr.address.startswith('::')
                for addr in addrs
            )
        ]

        return interfaces

    except ImportError:
        logger.warning("Psutil library not installed. Returns an empty list.")
        return []


def get_discovered_devices(device_ids):
    """
    Retrieves details of devices discovered during scanning.

    Args:
        device_ids (List[str]): List of device IDs

    Returns:
        List[NetworkDevice]: Device details
    """
    discovered_devices = []

    settings = Settings()
    storage = SQLiteStorage(settings)

    for device_id in device_ids:
        device = storage.get_network_devices(device_id)
        discovered_devices.append(device)

    return discovered_devices

@app.route("/targets/edit/<target_id>", methods=["GET", "POST"])
@login_required
def target_edit(target_id):
    """Edit an existing target."""
    target = storage.get_target(target_id)
    if not target:
        flash("Target not found", "danger")
        return redirect(url_for("targets_list"))

    form = TargetForm(obj=target)
    form.tags.data = ",".join(target.tags) if target.tags else ""

    if form.validate_on_submit():
        target.name = form.name.data
        target.hostname = form.hostname.data
        target.ip_address = form.ip_address.data
        target.os_type = form.os_type.data
        target.os_version = form.os_version.data
        target.description = form.description.data
        target.group = form.group.data
        target.tags = form.tags.data.split(",") if form.tags.data else []

        try:
            storage.save_target(target)
            flash(f"Target '{target.name}' successfully updated", "success")
            return redirect(url_for("targets_list"))
        except Exception as e:
            flash(f"Error updating target: {str(e)}", "danger")

    return render_template("targets/form.html", form=form, title="Edit Target")


@app.route("/targets/delete/<target_id>", methods=["POST"])
@login_required
def target_delete(target_id):
    """Delete target."""
    try:
        success = storage.delete_target(target_id)
        if success:
            flash("Target successfully eliminated", "success")
        else:
            flash("Target not found", "danger")
    except Exception as e:
        flash(f"Error deleting target: {str(e)}", "danger")

    return redirect(url_for("targets_list"))


@app.route("/targets/view/<target_id>")
@login_required
def target_view(target_id):
    """View details of a target and its results."""
    target = storage.get_target(target_id)
    if not target:
        flash("Target not found", "danger")
        return redirect(url_for("targets_list"))

    results = storage.get_latest_results(target_id)

    total_checks = len(results)
    compliant = sum(1 for r in results if r.score >= settings.compliance_threshold)
    compliance_rate = (compliant / total_checks * 100) if total_checks > 0 else 0

    return render_template(
        "targets/view.html",
        target=target,
        results=results,
        total_checks=total_checks,
        compliant=compliant,
        compliance_rate=compliance_rate
    )


@app.route("/checks")
@login_required
def checks_list():
    """Show the list of available controls."""
    checks = storage.get_all_checks()

    categories = {}
    for check in checks:
        category = check.category if check.category else "Altro"
        if category not in categories:
            categories[category] = []
        categories[category].append(check)

    return render_template("checks/list.html", categories=categories)

@app.route("/checks/view/<check_id>")
@login_required
def check_view(check_id):
    """View details of a control."""
    check = storage.get_check(check_id)
    if not check:
        flash("Check not found", "danger")
        return redirect(url_for("checks_list"))

    results = storage.get_results_by_check(check_id)

    return render_template("checks/view.html", check=check, results=results)


@app.route("/audits/run", methods=["GET", "POST"])
@login_required
def audit_run():
    """Perform a new audit."""
    targets = storage.get_all_targets()
    checks = storage.get_all_checks()

    if request.method == "POST":
        target_id = request.form.get("target_id")
        check_ids = request.form.getlist("check_ids")
        parallel = request.form.get("parallel") == "on"

        if not target_id:
            flash("Select a target", "danger")
            return render_template("audits/run.html", targets=targets, checks=checks)

        if not check_ids:
            flash("Select at least one control", "danger")
            return render_template("audits/run.html", targets=targets, checks=checks)

        target = storage.get_target(target_id)
        if not target:
            flash("Target not found", "danger")
            return render_template("audits/run.html", targets=targets, checks=checks)

        try:
            results = engine.run_checks(
                target=target,
                check_ids=check_ids,
                parallel=parallel
            )

            flash(f"Audit completed successfully. {len(results)} checks performed.", "success")
            return redirect(url_for("target_view", target_id=target_id))
        except Exception as e:
            flash(f"Error while running audit: {str(e)}", "danger")

    return render_template("audits/run.html", targets=targets, checks=checks)


@app.route("/audits/scheduled")
@login_required
def scheduled_audits_list():
    """Show the list of scheduled audits."""
    scheduled_audits = storage.get_all_scheduled_audits()
    return render_template("audits/scheduled_list.html", scheduled_audits=scheduled_audits)


@app.route("/audits/scheduled/add", methods=["GET", "POST"])
@login_required
def scheduled_audit_add():
    """Adds a new scheduled audit."""
    form = ScheduledAuditForm()

    targets = storage.get_all_targets()
    form.target_ids.choices = [(t.id, t.name) for t in targets]

    checks = storage.get_all_checks()
    form.check_ids.choices = [(c.id, f"{c.id} - {c.name}") for c in checks]

    if form.validate_on_submit():
        scheduled_audit = ScheduledAudit(
            name=form.name.data,
            description=form.description.data,
            target_ids=form.target_ids.data,
            check_ids=form.check_ids.data,
            frequency=form.frequency.data,
            day_of_week=form.day_of_week.data if form.frequency.data == "weekly" else None,
            day_of_month=form.day_of_month.data if form.frequency.data == "monthly" else None,
            hour=form.hour.data,
            minute=form.minute.data,
            enabled=form.enabled.data,
            notify_on_completion=form.notify_on_completion.data,
            notify_email=form.notify_email.data
        )

        if hasattr(scheduler, "_calculate_next_run"):
            scheduler._calculate_next_run(scheduled_audit)

        try:
            storage.save_scheduled_audit(scheduled_audit)
            flash(f"Scheduled audit '{scheduled_audit.name}' successfully added", "success")
            return redirect(url_for("scheduled_audits_list"))
        except Exception as e:
            flash(f"Error adding scheduled audit: {str(e)}", "danger")

    return render_template("audits/scheduled_form.html", form=form, title="Add Scheduled Audit")


@app.route("/audits/scheduled/edit/<scheduled_id>", methods=["GET", "POST"])
@login_required
def scheduled_audit_edit(scheduled_id):
    """Edit a scheduled audit."""
    scheduled_audit = storage.get_scheduled_audit(scheduled_id)
    if not scheduled_audit:
        flash("Planned Audit Not Found", "danger")
        return redirect(url_for("scheduled_audits_list"))

    form = ScheduledAuditForm(obj=scheduled_audit)

    targets = storage.get_all_targets()
    form.target_ids.choices = [(t.id, t.name) for t in targets]

    checks = storage.get_all_checks()
    form.check_ids.choices = [(c.id, f"{c.id} - {c.name}") for c in checks]

    if form.validate_on_submit():
        scheduled_audit.name = form.name.data
        scheduled_audit.description = form.description.data
        scheduled_audit.target_ids = form.target_ids.data
        scheduled_audit.check_ids = form.check_ids.data
        scheduled_audit.frequency = form.frequency.data
        scheduled_audit.day_of_week = form.day_of_week.data if form.frequency.data == "weekly" else None
        scheduled_audit.day_of_month = form.day_of_month.data if form.frequency.data == "monthly" else None
        scheduled_audit.hour = form.hour.data
        scheduled_audit.minute = form.minute.data
        scheduled_audit.enabled = form.enabled.data
        scheduled_audit.notify_on_completion = form.notify_on_completion.data
        scheduled_audit.notify_email = form.notify_email.data

        if hasattr(scheduler, "_calculate_next_run"):
            scheduler._calculate_next_run(scheduled_audit)

        try:
            storage.save_scheduled_audit(scheduled_audit)
            flash(f"Scheduled audit '{scheduled_audit.name}' updated successfully", "success")
            return redirect(url_for("scheduled_audits_list"))
        except Exception as e:
            flash(f"Error updating scheduled audit: {str(e)}", "danger")

    return render_template("audits/scheduled_form.html", form=form, title="Edit Scheduled Audit")


@app.route("/audits/scheduled/delete/<scheduled_id>", methods=["POST"])
@login_required
def scheduled_audit_delete(scheduled_id):
    """Delete a scheduled audit."""
    try:
        success = storage.delete_scheduled_audit(scheduled_id)
        if success:
            flash("Planned Audit successfully deleted", "success")
        else:
            flash("Planned Audit Not Found", "danger")
    except Exception as e:
        flash(f"Error deleting scheduled audit: {str(e)}", "danger")

    return redirect(url_for("scheduled_audits_list"))


@app.route("/reports")
@login_required
def reports_list():
    """Show the list of generated reports."""
    reports = storage.get_all_reports()
    return render_template("reports/list.html", reports=reports)


@app.route("/reports/generate", methods=["GET", "POST"])
@login_required
def report_generate():
    """Generate a new report."""
    form = ReportForm()

    targets = storage.get_all_targets()
    form.target_ids.choices = [(t.id, t.name) for t in targets]
    form.target_ids.choices.insert(0, ("", "All targets"))

    checks = storage.get_all_checks()
    categories = list(set(c.category for c in checks if c.category))
    form.categories.choices = [(c, c) for c in categories]

    if form.validate_on_submit():
        check_ids = None
        if form.categories.data:
            check_ids = []
            for check in checks:
                if check.category in form.categories.data:
                    check_ids.append(check.id)

        target_ids = [t_id for t_id in form.target_ids.data if t_id]
        if not target_ids:  # Se nessun target selezionato, usa tutti
            target_ids = [t.id for t in targets]

        try:
            report_data = result_manager.generate_report(
                target_ids=target_ids,
                check_ids=check_ids,
                format_type=form.format.data
            )

            from absc_audit.storage.models import AuditReport
            report = AuditReport(
                name=form.name.data,
                description=form.description.data,
                target_ids=target_ids,
                check_ids=check_ids,
                format=form.format.data
            )

            if isinstance(report_data, dict):
                report.compliance_stats = report_data.get("compliance_stats", {})
                report.result_summary = report_data.get("result_summary", {})
                report.result_ids = [r.get("id") for r in report_data.get("results", [])]

            storage.save_report(report)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.{form.format.data}"
            output_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

            if form.format.data == "json":
                with open(output_path, "w") as f:
                    json.dump(report_data, f, indent=2, default=str)
            else:
                with open(output_path, "w") as f:
                    f.write(report_data)

            return send_file(output_path, as_attachment=True, download_name=filename)
        except Exception as e:
            flash(f"Error generating report: {str(e)}", "danger")

    return render_template("reports/generate.html", form=form)


@app.route("/users")
@login_required
def users_list():
    """Show the list of users."""
    if current_user.role != "admin":
        flash("You do not have permission to access this page", "danger")
        return redirect(url_for("dashboard"))

    users = storage.get_all_users()
    return render_template("users/list.html", users=users)

@app.route("/users/add", methods=["GET", "POST"])
@login_required
def user_add():
    """Add a new user."""
    if current_user.role != "admin":
        flash("You do not have permission to access this page", "danger")
        return redirect(url_for("dashboard"))

    form = UserForm()
    if form.validate_on_submit():
        existing_users = storage.get_users_by_username(form.username.data)
        if existing_users:
            flash("Username already in use", "danger")
            return render_template("users/form.html", form=form, title="Add User")

        from absc_audit.storage.models import UserAccount
        user_account = UserAccount(
            username=form.username.data,
            password_hash=generate_password_hash(form.password.data),
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            role=form.role.data,
            enabled=form.enabled.data
        )

        try:
            storage.save_user(user_account)
            flash(f"User '{user_account.username}' added successfully", "success")
            return redirect(url_for("users_list"))
        except Exception as e:
            flash(f"Error adding user: {str(e)}", "danger")

    return render_template("users/form.html", form=form, title="Add User")


@app.route("/users/edit/<user_id>", methods=["GET", "POST"])
@login_required
def user_edit(user_id):
    """Edit an existing user."""
    if current_user.role != "admin" and current_user.id != user_id:
        flash("You do not have permission to access this page", "danger")
        return redirect(url_for("dashboard"))

    user_account = storage.get_user(user_id)
    if not user_account:
        flash("User not found", "danger")
        return redirect(url_for("users_list"))

    form = UserForm(obj=user_account)
    # Remove password field validation to not require password always
    form.password.validators = []

    if form.validate_on_submit():
        # Update user
        user_account.email = form.email.data
        user_account.first_name = form.first_name.data
        user_account.last_name = form.last_name.data

        # Only admins can modify role and status
        if current_user.role == "admin":
            user_account.role = form.role.data
            user_account.enabled = form.enabled.data

        # Update password if specified
        if form.password.data:
            user_account.password_hash = generate_password_hash(form.password.data)

        # Save user
        try:
            storage.save_user(user_account)
            flash(f"User '{user_account.username}' updated successfully", "success")

            if current_user.role == "admin":
                return redirect(url_for("users_list"))
            else:
                return redirect(url_for("profile"))
        except Exception as e:
            flash(f"Error updating user: {str(e)}", "danger")

    return render_template("users/form.html", form=form, title="Edit User")


@app.route("/users/delete/<user_id>", methods=["POST"])
@login_required
def user_delete(user_id):
    """Delete a user."""
    if current_user.role != "admin":
        flash("You do not have permission to access this page", "danger")
        return redirect(url_for("dashboard"))

    if current_user.id == user_id:
        flash("You cannot delete your own user", "danger")
        return redirect(url_for("users_list"))

    try:
        success = storage.delete_user(user_id)
        if success:
            flash("User deleted successfully", "success")
        else:
            flash("User not found", "danger")
    except Exception as e:
        flash(f"Error deleting user: {str(e)}", "danger")

    return redirect(url_for("users_list"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """View and modify the current user's profile."""
    user_account = storage.get_user(current_user.id)
    if not user_account:
        flash("User not found", "danger")
        return redirect(url_for("dashboard"))

    form = ProfileForm(obj=user_account)

    if form.validate_on_submit():
        # Verify current password
        if check_password_hash(user_account.password_hash, form.current_password.data):
            # Update profile
            user_account.email = form.email.data
            user_account.first_name = form.first_name.data
            user_account.last_name = form.last_name.data

            # Update password if specified
            if form.new_password.data:
                user_account.password_hash = generate_password_hash(form.new_password.data)

            # Save user
            try:
                storage.save_user(user_account)
                flash("Profile updated successfully", "success")
                return redirect(url_for("profile"))
            except Exception as e:
                flash(f"Error updating profile: {str(e)}", "danger")
        else:
            flash("Current password is invalid", "danger")

    return render_template("users/profile.html", form=form, user=user_account)


@app.route("/api/results/<check_id>")
@login_required
def api_results(check_id):
    """API to get check results in JSON format."""
    results = storage.get_results_by_check(check_id)

    # Convert results to JSON
    results_json = []
    for result in results:
        target = storage.get_target(result.target_id)
        results_json.append({
            "id": result.id,
            "check_id": result.check_id,
            "target_id": result.target_id,
            "target_name": target.name if target else "Unknown Target",
            "timestamp": result.timestamp.isoformat(),
            "status": result.status,
            "score": result.score,
            "compliant": result.score >= settings.compliance_threshold
        })

    return jsonify(results_json)


@app.route("/api/targets")
@login_required
def api_targets():
    """API to get the list of targets in JSON format."""
    targets = storage.get_all_targets()

    # Convert targets to JSON
    targets_json = []
    for target in targets:
        targets_json.append({
            "id": target.id,
            "name": target.name,
            "hostname": target.hostname,
            "ip_address": target.ip_address,
            "os_type": target.os_type,
            "group": target.group
        })

    return jsonify(targets_json)


@app.route("/api/stats")
@login_required
def api_stats():
    """API to get general statistics in JSON format."""
    targets_count = len(storage.get_all_targets())
    latest_results = storage.get_latest_results()

    # Calculate compliance statistics
    total_checks = len(latest_results)
    compliant = sum(1 for r in latest_results if r.score >= settings.compliance_threshold)
    compliance_rate = (compliant / total_checks * 100) if total_checks > 0 else 0

    # Category statistics
    checks = storage.get_all_checks()
    categories = {}
    for check in checks:
        if check.category not in categories:
            categories[check.category] = {
                "name": check.category,
                "total": 0,
                "compliant": 0
            }

    # Calculate category statistics
    for result in latest_results:
        check = storage.get_check(result.check_id)
        if check and check.category in categories:
            categories[check.category]["total"] += 1
            if result.score >= settings.compliance_threshold:
                categories[check.category]["compliant"] += 1

    # Calculate category compliance percentage
    for category in categories.values():
        if category["total"] > 0:
            category["compliance_rate"] = (category["compliant"] / category["total"]) * 100
        else:
            category["compliance_rate"] = 0

    stats = {
        "targets_count": targets_count,
        "total_checks": total_checks,
        "compliant": compliant,
        "compliance_rate": compliance_rate,
        "categories": list(categories.values())
    }

    return jsonify(stats)


@app.route("/api/run_check", methods=["POST"])
@login_required
def api_run_check():
    """API to run a specific check."""
    data = request.get_json()

    if not data or "target_id" not in data or "check_id" not in data:
        return jsonify({"success": False, "error": "Missing data"}), 400

    target_id = data["target_id"]
    check_id = data["check_id"]

    # Get the target
    target = storage.get_target(target_id)
    if not target:
        return jsonify({"success": False, "error": "Target not found"}), 404

    # Verify that the check exists
    check = storage.get_check(check_id)
    if not check:
        return jsonify({"success": False, "error": "Check not found"}), 404

    # Run the check
    try:
        result = engine.run_check(check_id, target)

        return jsonify({
            "success": True,
            "result": {
                "id": result.id,
                "check_id": result.check_id,
                "target_id": result.target_id,
                "timestamp": result.timestamp.isoformat(),
                "status": result.status,
                "score": result.score,
                "compliant": result.score >= settings.compliance_threshold,
                "notes": result.notes
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# Make get_target function available in templates
@app.context_processor
def utility_processor():
    def get_target(target_id):
        """Retrieve a target by its ID for use in templates."""
        return storage.get_target(target_id)

    return {'get_target': get_target}

# Error handling
@app.errorhandler(404)
def page_not_found(e):
    """Handles 404 error (page not found)."""
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 error (internal server error)."""
    return render_template("errors/500.html"), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5003)))