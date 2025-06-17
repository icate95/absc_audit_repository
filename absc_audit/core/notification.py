import smtplib
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional

from absc_audit.config.settings import Settings
from absc_audit.storage.models import AuditResult, Target
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class NotificationService:
    """
    Servizio di notifiche per il sistema di audit.

    Questa classe si occupa di inviare notifiche via email
    per eventi significativi come non conformità o errori.
    """

    def __init__(self, settings: Optional[Settings] = None):
        """
        Inizializza il servizio di notifiche.

        Args:
            settings: Configurazioni del sistema (opzionale)
        """
        self.settings = settings or Settings()
        self.enabled = self.settings.enable_notifications

    def send_non_compliance_notification(self, result: AuditResult, target: Optional[Target] = None) -> bool:
        """
        Invia una notifica di non conformità.

        Args:
            result: Risultato dell'audit non conforme
            target: Target associato (opzionale)

        Returns:
            True se l'invio ha successo, False altrimenti
        """
        if not self.enabled:
            logger.debug("Notifications are disabled")
            return False

        try:
            subject = f"[ABSC Audit] Non conformità rilevata: {result.check_id}"

            # Prepara il corpo del messaggio
            body = f"""
            <h2>Non conformità rilevata</h2>
            <p><strong>Check ID:</strong> {result.check_id}</p>
            <p><strong>Target:</strong> {target.name if target else result.target_id}</p>
            <p><strong>Timestamp:</strong> {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Status:</strong> {result.status}</p>
            <p><strong>Score:</strong> {result.score}%</p>

            <h3>Dettagli</h3>
            <pre>{result.details}</pre>

            <p><strong>Note:</strong> {result.notes}</p>
            """

            # Invia l'email
            return self._send_email(subject, body, is_html=True)

        except Exception as e:
            logger.error(f"Error sending non-compliance notification: {str(e)}")
            return False

    def send_audit_summary(self, results: List[AuditResult], target: Optional[Target] = None) -> bool:
        """
        Invia un riepilogo dell'audit.

        Args:
            results: Lista di risultati dell'audit
            target: Target associato (opzionale)

        Returns:
            True se l'invio ha successo, False altrimenti
        """
        if not self.enabled:
            logger.debug("Notifications are disabled")
            return False

        try:
            subject = f"[ABSC Audit] Riepilogo audit: {target.name if target else 'Multiple targets'}"

            # Calcola statistiche
            total = len(results)
            compliant = sum(1 for r in results if r.score >= self.settings.compliance_threshold)
            non_compliant = total - compliant
            compliance_rate = (compliant / total) * 100 if total > 0 else 0

            # Prepara il corpo del messaggio
            body = f"""
            <h2>Riepilogo audit ABSC</h2>
            <p><strong>Target:</strong> {target.name if target else 'Multiple targets'}</p>
            <p><strong>Timestamp:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

            <h3>Statistiche</h3>
            <p>Controlli totali: {total}</p>
            <p>Controlli conformi: {compliant}</p>
            <p>Controlli non conformi: {non_compliant}</p>
            <p>Tasso di conformità: {compliance_rate:.2f}%</p>

            <h3>Controlli non conformi</h3>
            <table border="1" cellpadding="5">
                <tr>
                    <th>Check ID</th>
                    <th>Status</th>
                    <th>Score</th>
                </tr>
            """

            # Aggiungi righe per i controlli non conformi
            for result in sorted(results, key=lambda r: r.score):
                if result.score < self.settings.compliance_threshold:
                    body += f"""
                    <tr>
                        <td>{result.check_id}</td>
                        <td>{result.status}</td>
                        <td>{result.score}%</td>
                    </tr>
                    """

            body += """
            </table>
            <p>Per maggiori dettagli, consultare il report completo.</p>
            """

            # Invia l'email
            return self._send_email(subject, body, is_html=True)

        except Exception as e:
            logger.error(f"Error sending audit summary: {str(e)}")
            return False

    def _send_email(self, subject: str, body: str, is_html: bool = False) -> bool:
        """
        Invia un'email.

        Args:
            subject: Oggetto dell'email
            body: Corpo dell'email
            is_html: Se il corpo è in formato HTML

        Returns:
            True se l'invio ha successo, False altrimenti
        """
        try:
            # Crea il messaggio
            msg = MIMEMultipart()
            msg['From'] = self.settings.smtp_username
            msg['To'] = self.settings.notification_email
            msg['Subject'] = subject

            # Aggiungi il corpo
            if is_html:
                msg.attach(MIMEText(body, 'html'))
            else:
                msg.attach(MIMEText(body, 'plain'))

            # Connessione al server SMTP
            server = smtplib.SMTP(self.settings.smtp_server, self.settings.smtp_port)

            # TLS se richiesto
            if self.settings.smtp_use_tls:
                server.starttls()

            # Login
            if self.settings.smtp_username and self.settings.smtp_password:
                server.login(self.settings.smtp_username, self.settings.smtp_password)

            # Invia l'email
            server.send_message(msg)
            server.quit()

            logger.info(f"Email sent to {self.settings.notification_email}: {subject}")
            return True

        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            return False