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


def _whatsapp_alert(ip: str, score: int) -> None:
    from twilio.rest import Client

    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    body = (
        f"⚠️ ForenHive ALERTE\n"
        f"IP : {ip}\n"
        f"Risk Score : {score}/100\n"
        f"Niveau : HIGH — Vérification requise."
    )
    msg = client.messages.create(
        from_=f"whatsapp:{TWILIO_WA_NUMBER}",
        to=DEST_WA,
        body=body,
    )
    log.info("WhatsApp alert sent  ip=%s score=%d sid=%s", ip, score, msg.sid)


def _call_alert(ip: str, score: int) -> None:
    from twilio.rest import Client
    from twilio.twiml.voice_response import VoiceResponse

    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    ip_spoken = ip.replace(".", " point ")
    resp = VoiceResponse()
    resp.say(
        f"Alerte ForenHive. Adresse I P {ip_spoken} "
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
    log.info("Voice call alert initiated  ip=%s score=%d sid=%s", ip, score, call.sid)


def send_alert(ip: str, score: int) -> None:
    """Dispatch WhatsApp (score 61-89) or voice call (score ≥ 90) alert."""
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        log.warning("Twilio credentials not configured — alert skipped for %s", ip)
        return
    try:
        if score >= 80:
            _call_alert(ip, score)
        elif score > 60:
            _whatsapp_alert(ip, score)
    except Exception as exc:
        log.error("Alert dispatch failed  ip=%s score=%d error=%s", ip, score, exc)
