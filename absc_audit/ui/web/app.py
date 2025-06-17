# absc_audit/ui/web/app.py

"""
Web Application - Applicazione web per il sistema di audit ABSC.

Questo modulo implementa l'applicazione web Flask per il sistema di audit.
"""

import os
import json
from datetime import datetime
from unicodedata import category

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from absc_audit.config.settings import Settings
from absc_audit.core.engine import AuditEngine, CheckRegistry
from absc_audit.core.result_manager import ResultManager
from absc_audit.core.scheduler import Scheduler
from absc_audit.storage.sqlite import SQLiteStorage
from absc_audit.ui.web.forms import (
    LoginForm, RegisterForm, TargetForm, ScheduledAuditForm,
    UserForm, ProfileForm, ReportForm
)
from absc_audit.ui.web.models import User
from absc_audit.storage.models import Target, AuditCheck, ScheduledAudit
from absc_audit.ui.web.utils import init_registry

# Inizializza l'applicazione Flask
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "development-key")
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Inizializza LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Per favore, effettua il login per accedere a questa pagina."

# Inizializza componenti ABSC Audit
settings = Settings()
storage = SQLiteStorage(settings)
result_manager = ResultManager(settings)
result_manager.configure_storage(storage)
engine = AuditEngine(settings)
engine.register_result_manager(result_manager)
scheduler = Scheduler(engine, storage, settings)

# Registra i controlli disponibili
init_registry(engine, storage)

# Avvia lo scheduler (se necessario)
if os.environ.get("ENABLE_SCHEDULER", "false").lower() == "true":
    scheduler.start()


@login_manager.user_loader
def load_user(user_id):
    """Carica un utente dal database."""
    user_account = storage.get_user(user_id)
    if user_account:
        return User.from_user_account(user_account)
    return None


# Rotte per l'autenticazione
@app.route("/login", methods=["GET", "POST"])
def login():
    """Gestisce il login degli utenti."""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Cerca l'utente nel database
        users = storage.get_users_by_username(username)
        if not users:
            flash("Username o password non validi", "danger")
            return render_template("login.html", form=form)

        user_account = users[0]
        if check_password_hash(user_account.password_hash, password):
            # Aggiorna l'ultimo login
            user_account.last_login = datetime.now()
            storage.save_user(user_account)

            # Effettua il login
            user = User.from_user_account(user_account)
            login_user(user)

            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))
        else:
            flash("Username o password non validi", "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    """Gestisce il logout degli utenti."""
    logout_user()
    flash("Hai effettuato il logout con successo", "success")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Gestisce la registrazione di nuovi utenti."""
    # Verifica se è il primo utente (diventa admin)
    is_first_user = len(storage.get_all_users()) == 0

    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        # Verifica se l'utente esiste già
        existing_users = storage.get_users_by_username(username)
        if existing_users:
            flash("Username già in uso", "danger")
            return render_template("register.html", form=form, is_first_user=is_first_user)

        # Crea il nuovo utente
        from absc_audit.storage.models import UserAccount
        user_account = UserAccount(
            username=username,
            password_hash=generate_password_hash(password),
            email=email,
            first_name=first_name,
            last_name=last_name,
            role="admin" if is_first_user else "user"
        )

        # Salva l'utente
        try:
            storage.save_user(user_account)
            flash("Registrazione completata con successo. Puoi effettuare il login.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"Errore durante la registrazione: {str(e)}", "danger")

    return render_template("register.html", form=form, is_first_user=is_first_user)


# Rotte per il dashboard e le pagine principali
@app.route("/")
@login_required
def dashboard():
    """Mostra la dashboard principale."""
    # Ottieni statistiche per la dashboard
    targets_count = len(storage.get_all_targets())
    latest_results = storage.get_latest_results()

    # Calcola statistiche di conformità
    total_checks = len(latest_results)
    compliant = sum(1 for r in latest_results if r.score >= settings.compliance_threshold)
    compliance_rate = (compliant / total_checks * 100) if total_checks > 0 else 0

    # Ottieni gli ultimi audit eseguiti
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
    """Mostra la lista dei target."""
    targets = storage.get_all_targets()

    # Recupera le categorie dai controlli disponibili
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
    """Aggiunge un nuovo target."""
    form = TargetForm()
    if form.validate_on_submit():
        # Crea un nuovo target
        target = Target(
            name=form.name.data,
            hostname=form.hostname.data,
            ip_address=form.ip_address.data,
            os_type=form.os_type.data,
            os_version=form.os_version.data,
            description=form.description.data,
            group=form.group.data,
            tags=form.tags.data.split(",") if form.tags.data else []
        )

        # Salva il target
        try:
            storage.save_target(target)
            flash(f"Target '{target.name}' aggiunto con successo", "success")
            return redirect(url_for("targets_list"))
        except Exception as e:
            flash(f"Errore durante l'aggiunta del target: {str(e)}", "danger")

    return render_template("targets/form.html", form=form, title="Aggiungi Target")


@app.route("/targets/edit/<target_id>", methods=["GET", "POST"])
@login_required
def target_edit(target_id):
    """Modifica un target esistente."""
    target = storage.get_target(target_id)
    if not target:
        flash("Target non trovato", "danger")
        return redirect(url_for("targets_list"))

    form = TargetForm(obj=target)
    form.tags.data = ",".join(target.tags) if target.tags else ""

    if form.validate_on_submit():
        # Aggiorna il target
        target.name = form.name.data
        target.hostname = form.hostname.data
        target.ip_address = form.ip_address.data
        target.os_type = form.os_type.data
        target.os_version = form.os_version.data
        target.description = form.description.data
        target.group = form.group.data
        target.tags = form.tags.data.split(",") if form.tags.data else []

        # Salva il target
        try:
            storage.save_target(target)
            flash(f"Target '{target.name}' aggiornato con successo", "success")
            return redirect(url_for("targets_list"))
        except Exception as e:
            flash(f"Errore durante l'aggiornamento del target: {str(e)}", "danger")

    return render_template("targets/form.html", form=form, title="Modifica Target")


@app.route("/targets/delete/<target_id>", methods=["POST"])
@login_required
def target_delete(target_id):
    """Elimina un target."""
    try:
        success = storage.delete_target(target_id)
        if success:
            flash("Target eliminato con successo", "success")
        else:
            flash("Target non trovato", "danger")
    except Exception as e:
        flash(f"Errore durante l'eliminazione del target: {str(e)}", "danger")

    return redirect(url_for("targets_list"))


@app.route("/targets/view/<target_id>")
@login_required
def target_view(target_id):
    """Visualizza i dettagli di un target e i suoi risultati."""
    target = storage.get_target(target_id)
    if not target:
        flash("Target non trovato", "danger")
        return redirect(url_for("targets_list"))

    # Ottieni i risultati più recenti per questo target
    results = storage.get_latest_results(target_id)

    # Calcola statistiche di conformità
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
    """Mostra la lista dei controlli disponibili."""
    checks = storage.get_all_checks()

    # Manca questa parte: organizzare i controlli per categoria
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
    """Visualizza i dettagli di un controllo."""
    check = storage.get_check(check_id)
    if not check:
        flash("Controllo non trovato", "danger")
        return redirect(url_for("checks_list"))

    # Ottieni i risultati più recenti per questo controllo
    results = storage.get_results_by_check(check_id)

    return render_template("checks/view.html", check=check, results=results)


@app.route("/audits/run", methods=["GET", "POST"])
@login_required
def audit_run():
    """Esegue un nuovo audit."""
    targets = storage.get_all_targets()
    checks = storage.get_all_checks()

    if request.method == "POST":
        target_id = request.form.get("target_id")
        check_ids = request.form.getlist("check_ids")
        parallel = request.form.get("parallel") == "on"

        if not target_id:
            flash("Seleziona un target", "danger")
            return render_template("audits/run.html", targets=targets, checks=checks)

        if not check_ids:
            flash("Seleziona almeno un controllo", "danger")
            return render_template("audits/run.html", targets=targets, checks=checks)

        # Ottieni il target
        target = storage.get_target(target_id)
        if not target:
            flash("Target non trovato", "danger")
            return render_template("audits/run.html", targets=targets, checks=checks)

        # Esegui l'audit
        try:
            results = engine.run_checks(
                target=target,
                check_ids=check_ids,
                parallel=parallel
            )

            flash(f"Audit completato con successo. Eseguiti {len(results)} controlli.", "success")
            return redirect(url_for("target_view", target_id=target_id))
        except Exception as e:
            flash(f"Errore durante l'esecuzione dell'audit: {str(e)}", "danger")

    return render_template("audits/run.html", targets=targets, checks=checks)


@app.route("/audits/scheduled")
@login_required
def scheduled_audits_list():
    """Mostra la lista degli audit pianificati."""
    scheduled_audits = storage.get_all_scheduled_audits()
    return render_template("audits/scheduled_list.html", scheduled_audits=scheduled_audits)


@app.route("/audits/scheduled/add", methods=["GET", "POST"])
@login_required
def scheduled_audit_add():
    """Aggiunge un nuovo audit pianificato."""
    form = ScheduledAuditForm()

    # Popola le scelte di target e controlli
    targets = storage.get_all_targets()
    form.target_ids.choices = [(t.id, t.name) for t in targets]

    checks = storage.get_all_checks()
    form.check_ids.choices = [(c.id, f"{c.id} - {c.name}") for c in checks]

    if form.validate_on_submit():
        # Crea un nuovo audit pianificato
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

        # Calcola il prossimo orario di esecuzione
        if hasattr(scheduler, "_calculate_next_run"):
            scheduler._calculate_next_run(scheduled_audit)

        # Salva l'audit pianificato
        try:
            storage.save_scheduled_audit(scheduled_audit)
            flash(f"Audit pianificato '{scheduled_audit.name}' aggiunto con successo", "success")
            return redirect(url_for("scheduled_audits_list"))
        except Exception as e:
            flash(f"Errore durante l'aggiunta dell'audit pianificato: {str(e)}", "danger")

    return render_template("audits/scheduled_form.html", form=form, title="Aggiungi Audit Pianificato")


@app.route("/audits/scheduled/edit/<scheduled_id>", methods=["GET", "POST"])
@login_required
def scheduled_audit_edit(scheduled_id):
    """Modifica un audit pianificato."""
    scheduled_audit = storage.get_scheduled_audit(scheduled_id)
    if not scheduled_audit:
        flash("Audit pianificato non trovato", "danger")
        return redirect(url_for("scheduled_audits_list"))

    form = ScheduledAuditForm(obj=scheduled_audit)

    # Popola le scelte di target e controlli
    targets = storage.get_all_targets()
    form.target_ids.choices = [(t.id, t.name) for t in targets]

    checks = storage.get_all_checks()
    form.check_ids.choices = [(c.id, f"{c.id} - {c.name}") for c in checks]

    if form.validate_on_submit():
        # Aggiorna l'audit pianificato
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

        # Calcola il prossimo orario di esecuzione
        if hasattr(scheduler, "_calculate_next_run"):
            scheduler._calculate_next_run(scheduled_audit)

        # Salva l'audit pianificato
        try:
            storage.save_scheduled_audit(scheduled_audit)
            flash(f"Audit pianificato '{scheduled_audit.name}' aggiornato con successo", "success")
            return redirect(url_for("scheduled_audits_list"))
        except Exception as e:
            flash(f"Errore durante l'aggiornamento dell'audit pianificato: {str(e)}", "danger")

    return render_template("audits/scheduled_form.html", form=form, title="Modifica Audit Pianificato")


@app.route("/audits/scheduled/delete/<scheduled_id>", methods=["POST"])
@login_required
def scheduled_audit_delete(scheduled_id):
    """Elimina un audit pianificato."""
    try:
        success = storage.delete_scheduled_audit(scheduled_id)
        if success:
            flash("Audit pianificato eliminato con successo", "success")
        else:
            flash("Audit pianificato non trovato", "danger")
    except Exception as e:
        flash(f"Errore durante l'eliminazione dell'audit pianificato: {str(e)}", "danger")

    return redirect(url_for("scheduled_audits_list"))


@app.route("/reports")
@login_required
def reports_list():
    """Mostra la lista dei report generati."""
    reports = storage.get_all_reports()
    return render_template("reports/list.html", reports=reports)


@app.route("/reports/generate", methods=["GET", "POST"])
@login_required
def report_generate():
    """Genera un nuovo report."""
    form = ReportForm()

    # Popola le scelte di target
    targets = storage.get_all_targets()
    form.target_ids.choices = [(t.id, t.name) for t in targets]
    form.target_ids.choices.insert(0, ("", "Tutti i target"))

    # Popola le scelte di categoria
    checks = storage.get_all_checks()
    categories = list(set(c.category for c in checks if c.category))
    form.categories.choices = [(c, c) for c in categories]

    if form.validate_on_submit():
        # Filtra i check IDs per categoria se specificato
        check_ids = None
        if form.categories.data:
            check_ids = []
            for check in checks:
                if check.category in form.categories.data:
                    check_ids.append(check.id)

        # Filtra i target IDs
        target_ids = [t_id for t_id in form.target_ids.data if t_id]
        if not target_ids:  # Se nessun target selezionato, usa tutti
            target_ids = [t.id for t in targets]

        # Genera il report
        try:
            # Genera il report
            report_data = result_manager.generate_report(
                target_ids=target_ids,
                check_ids=check_ids,
                format_type=form.format.data
            )

            # Crea un nuovo report
            from absc_audit.storage.models import AuditReport
            report = AuditReport(
                name=form.name.data,
                description=form.description.data,
                target_ids=target_ids,
                check_ids=check_ids,
                format=form.format.data
            )

            # Salva il report
            if isinstance(report_data, dict):
                report.compliance_stats = report_data.get("compliance_stats", {})
                report.result_summary = report_data.get("result_summary", {})
                report.result_ids = [r.get("id") for r in report_data.get("results", [])]

            storage.save_report(report)

            # Esporta il report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.{form.format.data}"
            output_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

            if form.format.data == "json":
                with open(output_path, "w") as f:
                    json.dump(report_data, f, indent=2, default=str)
            else:
                with open(output_path, "w") as f:
                    f.write(report_data)

            # Scarica il report
            return send_file(output_path, as_attachment=True, download_name=filename)
        except Exception as e:
            flash(f"Errore durante la generazione del report: {str(e)}", "danger")

    return render_template("reports/generate.html", form=form)


@app.route("/users")
@login_required
def users_list():
    """Mostra la lista degli utenti."""
    if current_user.role != "admin":
        flash("Non hai i permessi per accedere a questa pagina", "danger")
        return redirect(url_for("dashboard"))

    users = storage.get_all_users()
    return render_template("users/list.html", users=users)


@app.route("/users/add", methods=["GET", "POST"])
@login_required
def user_add():
    """Aggiunge un nuovo utente."""
    if current_user.role != "admin":
        flash("Non hai i permessi per accedere a questa pagina", "danger")
        return redirect(url_for("dashboard"))

    form = UserForm()
    if form.validate_on_submit():
        # Verifica se l'utente esiste già
        existing_users = storage.get_users_by_username(form.username.data)
        if existing_users:
            flash("Username già in uso", "danger")
            return render_template("users/form.html", form=form, title="Aggiungi Utente")

        # Crea il nuovo utente
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

        # Salva l'utente
        try:
            storage.save_user(user_account)
            flash(f"Utente '{user_account.username}' aggiunto con successo", "success")
            return redirect(url_for("users_list"))
        except Exception as e:
            flash(f"Errore durante l'aggiunta dell'utente: {str(e)}", "danger")

    return render_template("users/form.html", form=form, title="Aggiungi Utente")


@app.route("/users/edit/<user_id>", methods=["GET", "POST"])
@login_required
def user_edit(user_id):
    """Modifica un utente esistente."""
    if current_user.role != "admin" and current_user.id != user_id:
        flash("Non hai i permessi per accedere a questa pagina", "danger")
        return redirect(url_for("dashboard"))

    user_account = storage.get_user(user_id)
    if not user_account:
        flash("Utente non trovato", "danger")
        return redirect(url_for("users_list"))

    form = UserForm(obj=user_account)
    # Rimuovi il campo password per non richiedere sempre una nuova password
    form.password.validators = []

    if form.validate_on_submit():
        # Aggiorna l'utente
        user_account.email = form.email.data
        user_account.first_name = form.first_name.data
        user_account.last_name = form.last_name.data

        # Solo gli admin possono modificare ruolo e stato
        if current_user.role == "admin":
            user_account.role = form.role.data
            user_account.enabled = form.enabled.data

        # Aggiorna la password se specificata
        if form.password.data:
            user_account.password_hash = generate_password_hash(form.password.data)

        # Salva l'utente
        try:
            storage.save_user(user_account)
            flash(f"Utente '{user_account.username}' aggiornato con successo", "success")

            if current_user.role == "admin":
                return redirect(url_for("users_list"))
            else:
                return redirect(url_for("profile"))
        except Exception as e:
            flash(f"Errore durante l'aggiornamento dell'utente: {str(e)}", "danger")

    return render_template("users/form.html", form=form, title="Modifica Utente")


@app.route("/users/delete/<user_id>", methods=["POST"])
@login_required
def user_delete(user_id):
    """Elimina un utente."""
    if current_user.role != "admin":
        flash("Non hai i permessi per accedere a questa pagina", "danger")
        return redirect(url_for("dashboard"))

    if current_user.id == user_id:
        flash("Non puoi eliminare il tuo utente", "danger")
        return redirect(url_for("users_list"))

    try:
        success = storage.delete_user(user_id)
        if success:
            flash("Utente eliminato con successo", "success")
        else:
            flash("Utente non trovato", "danger")
    except Exception as e:
        flash(f"Errore durante l'eliminazione dell'utente: {str(e)}", "danger")

    return redirect(url_for("users_list"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Visualizza e modifica il profilo dell'utente corrente."""
    user_account = storage.get_user(current_user.id)
    if not user_account:
        flash("Utente non trovato", "danger")
        return redirect(url_for("dashboard"))

    form = ProfileForm(obj=user_account)

    if form.validate_on_submit():
        # Verifica la password corrente
        if check_password_hash(user_account.password_hash, form.current_password.data):
            # Aggiorna il profilo
            user_account.email = form.email.data
            user_account.first_name = form.first_name.data
            user_account.last_name = form.last_name.data

            # Aggiorna la password se specificata
            if form.new_password.data:
                user_account.password_hash = generate_password_hash(form.new_password.data)

            # Salva l'utente
            try:
                storage.save_user(user_account)
                flash("Profilo aggiornato con successo", "success")
                return redirect(url_for("profile"))
            except Exception as e:
                flash(f"Errore durante l'aggiornamento del profilo: {str(e)}", "danger")
        else:
            flash("Password corrente non valida", "danger")

    return render_template("users/profile.html", form=form, user=user_account)


@app.route("/api/results/<check_id>")
@login_required
def api_results(check_id):
    """API per ottenere i risultati di un controllo in formato JSON."""
    results = storage.get_results_by_check(check_id)

    # Converti i risultati in formato JSON
    results_json = []
    for result in results:
        target = storage.get_target(result.target_id)
        results_json.append({
            "id": result.id,
            "check_id": result.check_id,
            "target_id": result.target_id,
            "target_name": target.name if target else "Target sconosciuto",
            "timestamp": result.timestamp.isoformat(),
            "status": result.status,
            "score": result.score,
            "compliant": result.score >= settings.compliance_threshold
        })

    return jsonify(results_json)


@app.route("/api/targets")
@login_required
def api_targets():
    """API per ottenere la lista dei target in formato JSON."""
    targets = storage.get_all_targets()

    # Converti i target in formato JSON
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
    """API per ottenere le statistiche generali in formato JSON."""
    targets_count = len(storage.get_all_targets())
    latest_results = storage.get_latest_results()

    # Calcola statistiche di conformità
    total_checks = len(latest_results)
    compliant = sum(1 for r in latest_results if r.score >= settings.compliance_threshold)
    compliance_rate = (compliant / total_checks * 100) if total_checks > 0 else 0

    # Statistiche per categoria
    checks = storage.get_all_checks()
    categories = {}
    for check in checks:
        if check.category not in categories:
            categories[check.category] = {
                "name": check.category,
                "total": 0,
                "compliant": 0
            }

    # Calcola statistiche per categoria
    for result in latest_results:
        check = storage.get_check(result.check_id)
        if check and check.category in categories:
            categories[check.category]["total"] += 1
            if result.score >= settings.compliance_threshold:
                categories[check.category]["compliant"] += 1

    # Calcola percentuale di conformità per categoria
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
    """API per eseguire un controllo specifico."""
    data = request.get_json()

    if not data or "target_id" not in data or "check_id" not in data:
        return jsonify({"success": False, "error": "Dati mancanti"}), 400

    target_id = data["target_id"]
    check_id = data["check_id"]

    # Ottieni il target
    target = storage.get_target(target_id)
    if not target:
        return jsonify({"success": False, "error": "Target non trovato"}), 404

    # Verifica che il controllo esista
    check = storage.get_check(check_id)
    if not check:
        return jsonify({"success": False, "error": "Controllo non trovato"}), 404

    # Esegui il controllo
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


# Rendi disponibile la funzione get_target nei template
@app.context_processor
def utility_processor():
    def get_target(target_id):
        """Recupera un target dal suo ID per l'uso nei template."""
        return storage.get_target(target_id)

    return {'get_target': get_target}

# Gestione degli errori
@app.errorhandler(404)
def page_not_found(e):
    """Gestisce l'errore 404 (pagina non trovata)."""
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    """Gestisce l'errore 500 (errore interno del server)."""
    return render_template("errors/500.html"), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5003)))