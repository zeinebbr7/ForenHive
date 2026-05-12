from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from config import get_settings

log = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


class EmailService:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.env = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=select_autoescape(["html", "xml"]),
            enable_async=False,
        )

    def render(self, template: str, context: Dict[str, Any]) -> str:
        tmpl = self.env.get_template(template)
        return tmpl.render(**context)

    def _smtp_send(self, msg: EmailMessage) -> None:
        context = ssl.create_default_context()
        with smtplib.SMTP(
            self.settings.smtp_host, self.settings.smtp_port, timeout=20
        ) as server:
            server.ehlo()
            if self.settings.smtp_starttls:
                server.starttls(context=context)
                server.ehlo()
            if self.settings.smtp_user:
                server.login(self.settings.smtp_user, self.settings.smtp_password)
            server.send_message(msg)

    def send_alert(
        self,
        recipients: List[str],
        subject: str,
        context: Dict[str, Any],
        attachments: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        if not recipients:
            raise ValueError("no recipients configured")
        html = self.render("alert_email.html", context)
        plain = self._plain_fallback(context)

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.settings.smtp_from
        msg["To"] = ", ".join(recipients)
        msg.set_content(plain)
        msg.add_alternative(html, subtype="html")

        for att in attachments or []:
            msg.add_attachment(
                att["data"],
                maintype=att.get("maintype", "application"),
                subtype=att.get("subtype", "octet-stream"),
                filename=att["filename"],
            )
        self._smtp_send(msg)

    def send_test(self, recipients: List[str]) -> None:
        subject = "[FORENHIVE ALERT] TEST — Alert Pipeline Healthy"
        context = {
            "is_test": True,
            "severity": "TEST",
            "threat_type": "Alert pipeline self-test",
            "source_ip": "127.0.0.1",
            "country": "Local",
            "risk_score": 0,
            "attempts": 0,
            "mitre_tags": [],
            "honeypot": "n/a",
            "yara_match": None,
            "abuseipdb_score": None,
            "ioc_hash": "",
            "tsa_timestamp": "",
            "mistral_analysis": "This is a ForenHive SMTP self-test. No action required.",
            "timestamp": "now",
        }
        self.send_alert(recipients, subject, context)

    @staticmethod
    def _plain_fallback(ctx: Dict[str, Any]) -> str:
        mitre = ", ".join(ctx.get("mitre_tags") or []) or "—"
        lines = [
            f"ForenHive Alert — {ctx.get('severity', 'N/A')}",
            f"Threat     : {ctx.get('threat_type')}",
            f"Source IP  : {ctx.get('source_ip')} ({ctx.get('country')})",
            f"Honeypot   : {ctx.get('honeypot')}",
            f"Risk score : {ctx.get('risk_score')}/100",
            f"Attempts   : {ctx.get('attempts')}",
            f"MITRE      : {mitre}",
            "",
            "AI Analysis:",
            str(ctx.get("mistral_analysis") or "—"),
        ]
        return "\n".join(lines)


_svc: Optional[EmailService] = None


def get_email() -> EmailService:
    global _svc
    if _svc is None:
        _svc = EmailService()
    return _svc
