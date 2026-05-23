from __future__ import annotations

import logging
import os

from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_WA_NUMBER = os.environ.get("TWILIO_WA_NUMBER", "")
DEST_WA = os.environ.get("DEST_WA", "")


def _whatsapp_alert(
    ip: str, score: int, is_internal: bool = False, network_class: str = ""
) -> None:
    from twilio.rest import Client

    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    level = "CRITICAL" if score >= 70 else "HIGH"  # v2.0.0 CRITICAL cutoff
    if is_internal:
        body = (
            f"⚠️ [FORENHIVE] INSIDER THREAT\n"
            f"IP : {ip} (INTERNAL — {network_class.replace('_', ' ')})\n"
            f"Risk Score : {score}/100 · {level}\n"
            f"Attack from INSIDE the network — immediate investigation required."
        )
    else:
        body = (
            f"⚠️ [FORENHIVE] {level} ALERT\n"
            f"IP : {ip}\n"
            f"Risk Score : {score}/100\n"
            f"Verification required."
        )
    msg = client.messages.create(
        from_=f"whatsapp:{TWILIO_WA_NUMBER}",
        to=DEST_WA,
        body=body,
    )
    log.info(
        "WhatsApp alert sent  ip=%s score=%d is_internal=%s sid=%s", ip, score, is_internal, msg.sid
    )


def send_alert(ip: str, score: int, is_internal: bool = False, network_class: str = "") -> None:
    """Dispatch a WhatsApp alert for any score > 60 or any internal IP threat."""
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        log.warning("Twilio credentials not configured — alert skipped for %s", ip)
        return
    try:
        if score > 60 or is_internal:
            _whatsapp_alert(ip, score, is_internal=is_internal, network_class=network_class)
    except Exception as exc:
        log.error("Alert dispatch failed  ip=%s score=%d error=%s", ip, score, exc)
