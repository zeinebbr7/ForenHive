from __future__ import annotations

import logging
import os

from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN  = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_WA_NUMBER   = os.environ.get("TWILIO_WA_NUMBER", "")
TWILIO_PHONE       = os.environ.get("TWILIO_PHONE", "")
DEST_WA            = os.environ.get("DEST_WA", "")
DEST_PHONE         = os.environ.get("DEST_PHONE", "")


def _whatsapp_alert(ip: str, score: int, is_internal: bool = False, network_class: str = "") -> None:
    from twilio.rest import Client

    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    if is_internal:
        body = (
            f"[FORENHIVE] INSIDER THREAT DETECTED\n"
            f"Source IP : {ip} (INTERNAL — {network_class.replace('_', ' ')})\n"
            f"Risk Score : {score}/100\n"
            f"REMARQUE: This attack is coming from INSIDE the network.\n"
            f"Immediate investigation required."
        )
    else:
        body = (
            f"[FORENHIVE] HIGH RISK ALERT\n"
            f"Source IP : {ip}\n"
            f"Risk Score : {score}/100\n"
            f"Level : HIGH — Verification required."
        )
    msg = client.messages.create(
        from_=f"whatsapp:{TWILIO_WA_NUMBER}",
        to=DEST_WA,
        body=body,
    )
    log.info("WhatsApp alert sent  ip=%s score=%d is_internal=%s sid=%s", ip, score, is_internal, msg.sid)


def _call_alert(ip: str, score: int, is_internal: bool = False) -> None:
    from twilio.rest import Client
    from twilio.twiml.voice_response import VoiceResponse

    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    ip_spoken = ip.replace(".", " point ")
    resp = VoiceResponse()
    insider_warning = "Attention, attaque interne détectée. " if is_internal else ""
    resp.say(
        f"Alerte ForenHive. {insider_warning}"
        f"Adresse I P {ip_spoken} "
        f"a un score de risque critique de {score} sur cent. "
        f"Intervention immédiate requise.",
        voice="alice",
        language="fr-FR",
    )
    call = client.calls.create(
        to=DEST_PHONE,
        from_=TWILIO_PHONE,
        twiml=str(resp),
    )
    log.info("Voice call alert initiated  ip=%s score=%d is_internal=%s sid=%s", ip, score, is_internal, call.sid)


def send_alert(ip: str, score: int, is_internal: bool = False, network_class: str = "") -> None:
    """Dispatch WhatsApp (score 61-89) or voice call (score >= 90) alert.
    Insider threat always triggers regardless of score threshold."""
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        log.warning("Twilio credentials not configured — alert skipped for %s", ip)
        return
    try:
        if score >= 80 or is_internal:
            _call_alert(ip, score, is_internal=is_internal)
        elif score > 60:
            _whatsapp_alert(ip, score, is_internal=is_internal, network_class=network_class)
    except Exception as exc:
        log.error("Alert dispatch failed  ip=%s score=%d error=%s", ip, score, exc)
