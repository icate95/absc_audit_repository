"""
Result Manager - Gestione dei risultati degli audit ABSC.

Questo modulo implementa il gestore dei risultati, responsabile 
per la persistenza, l'analisi e il reporting dei risultati degli audit.
"""

import datetime
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Union, Any

from absc_audit.config.settings import Settings
from absc_audit.storage.models import AuditResult
from absc_audit.utils.logging import setup_logger

logger = setup_logger(__name__)


class ResultManager:
    """
    Gestore dei risultati degli audit.

    Questa classe si occupa di elaborare, salvare e analizzare
    i risultati prodotti dall'audit engine.
    """

    def __init__(self, settings: Optional[Settings] = None):
        """
        Inizializza il result manager.

        Args:
            settings: Configurazioni del sistema (opzionale)
        """
        self.settings = settings or Settings()
        self.storage_backend = None  # Sarà impostato durante la configurazione
        self.notification_service = None  # Servizio di notifica opzionale

    def configure_storage(self, storage_backend):
        """
        Configura il backend di storage per i risultati.

        Args:
            storage_backend: Istanza del backend di storage
        """
        self.storage_backend = storage_backend

    def configure_notification(self, notification_service):
        """
        Configura il servizio di notifica.

        Args:
            notification_service: Istanza del servizio di notifica
        """
        self.notification_service = notification_service

    def process_result(self, result: AuditResult) -> AuditResult:
        """
        Elabora e salva un risultato di audit.

        Args:
            result: Risultato dell'audit da elaborare

        Returns:
            Risultato elaborato
        """
        logger.info(f"Processing result for check {result.check_id} on target {result.target_id}")

        # Arricchisci il risultato con metadati
        result.processed_at = datetime.datetime.now()

        # Calcola il punteggio se non è già definito
        if result.score is None:
            result.score = self._calculate_score(result)

        # Determina la conformità in base alla soglia configurata
        compliant = result.score >= self.settings.compliance_threshold
        result.details["compliant"] = compliant

        # Salva il risultato nel backend di storage
        if self.storage_backend:
            try:
                self.storage_backend.save_result(result)
                logger.debug(f"Result {result.id} saved to storage")
            except Exception as e:
                logger.error(f"Failed to save result to storage: {str(e)}", exc_info=True)

        # Invia notifiche se necessario
        if self.notification_service and not compliant:
            try:
                self.notification_service.send_non_compliance_notification(result)
                logger.debug(f"Non-compliance notification sent for result {result.id}")
            except Exception as e:
                logger.error(f"Failed to send notification: {str(e)}", exc_info=True)

        return result

    def process_results(self, results: List[AuditResult]) -> List[AuditResult]:
        """
        Elabora e salva una lista di risultati di audit.

        Args:
            results: Lista di risultati da elaborare

        Returns:
            Lista di risultati elaborati
        """
        processed_results = []
        for result in results:
            processed_result = self.process_result(result)
            processed_results.append(processed_result)

        return processed_results

    def get_result(self, result_id: str) -> Optional[AuditResult]:
        """
        Recupera un risultato specifico dal backend di storage.

        Args:
            result_id: ID del risultato da recuperare

        Returns:
            Risultato recuperato o None se non trovato
        """
        if not self.storage_backend:
            logger.warning("No storage backend configured")
            return None

        return self.storage_backend.get_result(result_id)

    def get_results_by_target(self, target_id: str) -> List[AuditResult]:
        """
        Recupera tutti i risultati per un target specifico.

        Args:
            target_id: ID del target

        Returns:
            Lista di risultati per il target
        """
        if not self.storage_backend:
            logger.warning("No storage backend configured")
            return []

        return self.storage_backend.get_results_by_target(target_id)

    def get_results_by_check(self, check_id: str) -> List[AuditResult]:
        """
        Recupera tutti i risultati per un controllo specifico.

        Args:
            check_id: ID del controllo ABSC

        Returns:
            Lista di risultati per il controllo
        """
        if not self.storage_backend:
            logger.warning("No storage backend configured")
            return []

        return self.storage_backend.get_results_by_check(check_id)

    def get_latest_results(self, target_id: Optional[str] = None) -> List[AuditResult]:
        """
        Recupera i risultati più recenti, opzionalmente filtrati per target.

        Args:
            target_id: ID del target (opzionale)

        Returns:
            Lista di risultati più recenti
        """
        if not self.storage_backend:
            logger.warning("No storage backend configured")
            return []

        return self.storage_backend.get_latest_results(target_id)

    def generate_report(self,
                        target_ids: Optional[List[str]] = None,
                        check_ids: Optional[List[str]] = None,
                        format_type: str = "json") -> Union[str, Dict]:
        """
        Genera un report basato sui risultati degli audit.

        Args:
            target_ids: Lista di ID target da includere (opzionale)
            check_ids: Lista di ID controlli da includere (opzionale)
            format_type: Formato del report (json, csv, html, pdf)

        Returns:
            Report nel formato richiesto
        """
        if not self.storage_backend:
            logger.warning("No storage backend configured")
            return {} if format_type == "json" else ""

        # Recupera i risultati in base ai filtri
        results = self.storage_backend.get_filtered_results(target_ids, check_ids)

        # Genera le statistiche di compliance
        compliance_stats = self._calculate_compliance_stats(results)

        # Crea la struttura del report
        report = {
            "generated_at": datetime.datetime.now().isoformat(),
            "compliance_stats": compliance_stats,
            "results": [self._result_to_dict(r) for r in results]
        }

        # Formatta il report in base al tipo richiesto
        if format_type == "json":
            return report
        elif format_type == "csv":
            return self._to_csv(report)
        elif format_type == "html":
            return self._to_html(report)
        elif format_type == "pdf":
            return self._to_pdf(report)
        else:
            logger.warning(f"Unsupported report format: {format_type}")
            return report

    def export_results(self,
                       results: List[AuditResult],
                       format_type: str = "json",
                       output_path: Optional[str] = None) -> str:
        """
        Esporta i risultati in un file.

        Args:
            results: Lista di risultati da esportare
            format_type: Formato dell'esportazione (json, csv)
            output_path: Percorso del file di output (opzionale)

        Returns:
            Percorso del file esportato
        """
        if not output_path:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = self.settings.output_dir or "reports"
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, f"audit_results_{timestamp}.{format_type}")

        # Prepara i dati
        data = [self._result_to_dict(r) for r in results]

        # Esporta in base al formato
        if format_type == "json":
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2, default=str)
        elif format_type == "csv":
            csv_content = self._to_csv({"results": data})
            with open(output_path, "w") as f:
                f.write(csv_content)
        else:
            logger.warning(f"Unsupported export format: {format_type}")
            raise ValueError(f"Unsupported export format: {format_type}")

        logger.info(f"Results exported to {output_path}")
        return output_path

    def _calculate_score(self, result: AuditResult) -> float:
        """
        Calcola il punteggio di conformità per un risultato.

        Args:
            result: Risultato di cui calcolare il punteggio

        Returns:
            Punteggio da 0 a 100
        """
        # Implementazione di default, può essere sovrascritta
        if result.status == "ERROR":
            return 0

        if result.status == "No":
            return 0

        if result.status and result.status.startswith("Sì") or result.status.startswith("Si"):
            # Gestisci le varie sfumature di "Sì"
            if "completo" in result.status.lower() or "pieno" in result.status.lower():
                return 100
            elif "parziale" in result.status.lower():
                return 50
            else:
                return 70

        # Fallback per stati non riconosciuti
        return 0

    def _calculate_compliance_stats(self, results: List[AuditResult], average_score=None) -> Dict:
        """
        Calcola le statistiche di conformità per una lista di risultati.

        Args:
            results: Lista di risultati

        Returns:
            Dizionario con statistiche di conformità
        """
        if not results:
            return {
                "total_checks": 0,
                "compliant": one_compliant,
                "non_compliant": 0,
                "compliance_rate": 0,
                "average_score": 0 if average_score is None else round(average_score, 2)
            }

        # Aggiungi qui il codice mancante
        total = len(results)
        compliant = sum(1 for r in results if r.score >= self.settings.compliance_threshold)
        non_compliant = total - compliant
        compliance_rate = (compliant / total) * 100 if total > 0 else 0
        avg_score = sum(r.score for r in results) / total if total > 0 else 0

        if average_score is not None:
            avg_score = average_score

        return {
            "total_checks": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "compliance_rate": round(compliance_rate, 2),
            "average_score": round(avg_score, 2)
        }

    def _result_to_dict(self, result: AuditResult) -> Dict:
        """
        Converte un risultato in un dizionario serializzabile.

        Args:
            result: Risultato da convertire

        Returns:
            Dizionario rappresentante il risultato
        """
        return {
            "id": result.id,
            "check_id": result.check_id,
            "target_id": result.target_id,
            "timestamp": result.timestamp.isoformat(),
            "processed_at": result.processed_at.isoformat() if result.processed_at else None,
            "status": result.status,
            "score": result.score,
            "details": result.details,
            "notes": result.notes
        }

    def _to_csv(self, report: Dict) -> str:
        """
        Converte un report in formato CSV.

        Args:
            report: Report da convertire

        Returns:
            Stringa in formato CSV
        """
        import csv
        from io import StringIO

        output = StringIO()

        # Estrai i risultati dal report
        results = report.get("results", [])

        if not results:
            return ""

        # Determina le intestazioni utilizzando il primo risultato
        fieldnames = list(results[0].keys())

        # Rimuovi campi complessi che non possono essere rappresentati direttamente in CSV
        for complex_field in ["details", "raw_data"]:
            if complex_field in fieldnames:
                fieldnames.remove(complex_field)

        # Aggiungi intestazioni per le statistiche di conformità
        stats_fieldnames = []
        if "compliance_stats" in report:
            stats_fieldnames = [f"stat_{k}" for k in report["compliance_stats"].keys()]

        # Crea lo scrittore CSV
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        # Scrivi le righe dei risultati
        for result in results:
            # Filtra i campi complessi
            row = {k: v for k, v in result.items() if k in fieldnames}
            writer.writerow(row)

        return output.getvalue()

    def _to_html(self, report: Dict) -> str:
        """
        Converte un report in formato HTML.

        Args:
            report: Report da convertire

        Returns:
            Stringa in formato HTML
        """
        # Questo è un template HTML semplice
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Audit ABSC - Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                h1 { color: #2c3e50; }
                table { border-collapse: collapse; width: 100%; margin-top: 20px; }
                th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f2f2f2; }
                .compliant { color: green; }
                .non-compliant { color: red; }
                .stats { margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }
            </style>
        </head>
        <body>
            <h1>Audit ABSC - Report</h1>
            <p>Generato il: {generated_at}</p>

            <div class="stats">
                <h2>Statistiche di Conformità</h2>
                <p>Controlli totali: {total_checks}</p>
                <p>Controlli conformi: {compliant}</p>
                <p>Controlli non conformi: {non_compliant}</p>
                <p>Tasso di conformità: {compliance_rate}%</p>
                <p>Punteggio medio: {average_score}</p>
            </div>

            <h2>Risultati</h2>
            <table>
                <tr>
                    <th>Check ID</th>
                    <th>Target</th>
                    <th>Timestamp</th>
                    <th>Stato</th>
                    <th>Punteggio</th>
                    <th>Note</th>
                </tr>
                {result_rows}
            </table>
        </body>
        </html>
        """

        # Prepara i dati per il template
        stats = report.get("compliance_stats", {})
        results = report.get("results", [])

        # Genera le righe della tabella
        result_rows = ""
        for result in results:
            # Determina la classe CSS in base alla conformità
            css_class = "compliant" if result.get("score", 0) >= self.settings.compliance_threshold else "non-compliant"

            row = f"""
            <tr class="{css_class}">
                <td>{result.get('check_id', '')}</td>
                <td>{result.get('target_id', '')}</td>
                <td>{result.get('timestamp', '')}</td>
                <td>{result.get('status', '')}</td>
                <td>{result.get('score', '')}</td>
                <td>{result.get('notes', '')}</td>
            </tr>
            """
            result_rows += row

        # Compila il template
        html = html_template.format(
            generated_at=report.get("generated_at", ""),
            total_checks=stats.get("total_checks", 0),
            compliant=stats.get("compliant", 0),
            non_compliant=stats.get("non_compliant", 0),
            compliance_rate=stats.get("compliance_rate", 0),
            average_score=stats.get("average_score", 0),
            result_rows=result_rows
        )

        return html

    def _to_pdf(self, report: Dict) -> bytes:
        """
        Converte un report in formato PDF.

        Args:
            report: Report da convertire

        Returns:
            Contenuto del PDF come bytes
        """
        try:
            # Prima converti in HTML
            html_content = self._to_html(report)

            # Usa WeasyPrint per convertire HTML in PDF
            try:
                from weasyprint import HTML
                pdf_content = HTML(string=html_content).write_pdf()
                return pdf_content
            except ImportError:
                logger.warning("WeasyPrint not installed. Using alternative PDF generator.")

                # Alternativa usando ReportLab
                try:
                    from reportlab.lib.pagesizes import letter
                    from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
                    from reportlab.lib.styles import getSampleStyleSheet
                    from io import BytesIO

                    buffer = BytesIO()
                    doc = SimpleDocTemplate(buffer, pagesize=letter)
                    styles = getSampleStyleSheet()

                    # Costruisci il contenuto
                    content = []

                    # Titolo
                    content.append(Paragraph("Audit ABSC - Report", styles['Title']))
                    content.append(Paragraph(f"Generato il: {report.get('generated_at', '')}", styles['Normal']))

                    # Statistiche
                    stats = report.get("compliance_stats", {})
                    content.append(Paragraph("Statistiche di Conformità", styles['Heading2']))
                    content.append(Paragraph(f"Controlli totali: {stats.get('total_checks', 0)}", styles['Normal']))
                    content.append(
                        Paragraph(f"Tasso di conformità: {stats.get('compliance_rate', 0)}%", styles['Normal']))

                    # Risultati
                    content.append(Paragraph("Risultati", styles['Heading2']))

                    # Tabella dei risultati
                    results = report.get("results", [])
                    if results:
                        data = [["Check ID", "Target", "Stato", "Punteggio"]]
                        for result in results:
                            data.append([
                                result.get('check_id', ''),
                                result.get('target_id', ''),
                                result.get('status', ''),
                                str(result.get('score', ''))
                            ])

                        table = Table(data)
                        table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), '#f2f2f2'),
                            ('TEXTCOLOR', (0, 0), (-1, 0), '#333333'),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                            ('GRID', (0, 0), (-1, -1), 1, '#DDDDDD')
                        ]))
                        content.append(table)

                    # Costruisci il PDF
                    doc.build(content)
                    pdf_content = buffer.getvalue()
                    buffer.close()

                    return pdf_content
                except ImportError:
                    logger.error("Neither WeasyPrint nor ReportLab is installed.")
                    raise ValueError("PDF generation requires WeasyPrint or ReportLab")

        except Exception as e:
            logger.error(f"Error generating PDF: {str(e)}", exc_info=True)
            raise ValueError(f"Failed to generate PDF: {str(e)}")
