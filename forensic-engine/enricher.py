"""
ForenHive — Enrichissement des adresses IP
Pour chaque IP attaquante, on collecte :
  - Localisation géographique (pays, ville, coordonnées)  ← MaxMind GeoLite2
  - Détection anonymisation (Tor, VPN, Proxy)             ← IPLocate (gratuit)
  - Réputation / signalements                             ← AbuseIPDB
  - Ports ouverts / vulnérabilités connues                ← Shodan InternetDB (gratuit)
  - Informations réseau / organisation                    ← Whois / RDAP

Les résultats sont mis en cache dans PostgreSQL (24h) pour éviter
de re-contacter les APIs à chaque analyse.
"""

import ipaddress
import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

import psycopg2
import psycopg2.extras
import requests

import config

log = logging.getLogger("enricher")


# ══════════════════════════════════════════════════════════════════════════════
# FONCTIONS UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

def est_ip_privee(ip: str) -> bool:
    """Retourne True si l'IP appartient à un réseau privé (10.x, 192.168.x, 172.16.x...)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # IP invalide → traiter comme privée par sécurité


def maintenant_utc() -> datetime:
    """Retourne l'heure actuelle en UTC."""
    return datetime.now(timezone.utc)


def connexion_postgres():
    """Ouvre une connexion à la base PostgreSQL."""
    return psycopg2.connect(
        host=config.PG_HOST,
        port=config.PG_PORT,
        dbname=config.PG_DB,
        user=config.PG_USER,
        password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. GÉOLOCALISATION — MaxMind GeoLite2 (base locale, pas d'appel réseau)
# ══════════════════════════════════════════════════════════════════════════════

def _charger_geoip():
    """Charge les bases MaxMind au démarrage. Retourne (None, None) si absentes."""
    try:
        import geoip2.database
        reader_ville = geoip2.database.Reader(config.GEOIP_CITY_DB)
        reader_asn   = geoip2.database.Reader(config.GEOIP_ASN_DB)
        return reader_ville, reader_asn
    except Exception as e:
        log.warning(f"Bases GeoIP non disponibles : {e}")
        return None, None

_reader_ville, _reader_asn = _charger_geoip()


def geoip_lookup(ip: str) -> dict:
    """
    Retourne la localisation géographique d'une IP.
    Exemple : {"country": "Russia", "city": "Moscow", "lat": 55.7, "lon": 37.6, "asn": 12345}
    """
    resultat = {}

    # Localisation (pays, ville, coordonnées GPS)
    if _reader_ville:
        try:
            r = _reader_ville.city(ip)
            resultat.update({
                "country":      r.country.name,
                "country_code": r.country.iso_code,
                "city":         r.city.name,
                "lat":          r.location.latitude,
                "lon":          r.location.longitude,
            })
        except Exception:
            pass  # IP non trouvée dans la base (ex: IP privée)

    # Numéro ASN et opérateur
    if _reader_asn:
        try:
            r = _reader_asn.asn(ip)
            resultat.update({
                "asn": r.autonomous_system_number,
                "org": r.autonomous_system_organization,
            })
        except Exception:
            pass

    return resultat


# ══════════════════════════════════════════════════════════════════════════════
# 2. DÉTECTION ANONYMISATION — IPLocate (gratuit, sans clé)
# ══════════════════════════════════════════════════════════════════════════════

def iplocate_lookup(ip: str) -> dict:
    """
    Vérifie si l'IP utilise Tor, un VPN, un proxy ou un hébergeur.
    Exemple : {"is_tor": True, "is_vpn": False, "is_proxy": False}
    """
    try:
        reponse = requests.get(
            f"https://www.iplocate.io/api/lookup/{ip}",
            timeout=10
        )
        if reponse.status_code == 200:
            data = reponse.json()
            return {
                "is_tor":     data.get("is_tor",     False),
                "is_vpn":     data.get("is_vpn",     False),
                "is_proxy":   data.get("is_proxy",   False),
                "is_hosting": data.get("is_hosting", False),
            }
    except Exception as e:
        log.warning(f"IPLocate échoué pour {ip} : {e}")
    return {}


# ══════════════════════════════════════════════════════════════════════════════
# 3. RÉPUTATION — AbuseIPDB (nécessite une clé API gratuite)
# ══════════════════════════════════════════════════════════════════════════════

def abuseipdb_lookup(ip: str) -> dict:
    """
    Interroge AbuseIPDB pour obtenir le score de réputation de l'IP.
    Score 0 = propre, 100 = très malveillante.
    Exemple : {"abuse_score": 87, "total_reports": 42, "isp": "Hetzner Online"}
    """
    if not config.ABUSEIPDB_KEY:
        return {}  # clé non configurée → on passe

    try:
        reponse = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key":    config.ABUSEIPDB_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress":    ip,
                "maxAgeInDays": 90,
                "verbose":      "true"
            },
            timeout=10
        )
        if reponse.status_code == 200:
            data = reponse.json().get("data", {})
            return {
                "abuse_score":   data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "isp":           data.get("isp", ""),
                "is_tor":        data.get("isTor", False),
                "country_code":  data.get("countryCode", ""),
            }
        log.warning(f"AbuseIPDB a retourné {reponse.status_code} pour {ip}")
    except Exception as e:
        log.warning(f"AbuseIPDB échoué pour {ip} : {e}")
    return {}


# ══════════════════════════════════════════════════════════════════════════════
# 4. INFRASTRUCTURE — Shodan InternetDB (gratuit, sans clé)
# ══════════════════════════════════════════════════════════════════════════════

# Organisations connues comme fournisseurs de serveurs cloud/VPS
_ORGS_VPS = {
    "digitalocean", "linode", "vultr", "hetzner", "ovh", "scaleway",
    "amazon", "amazonaws", "google", "microsoft", "azure", "alibaba",
    "upcloud", "contabo", "hostinger", "ionos", "leaseweb",
}

# Tags qui indiquent un appareil IoT
_TAGS_IOT = {"iot", "embedded", "webcam", "router", "printer", "scada", "dvr", "camera"}


def classifier_machine(host: dict) -> str:
    """
    Détermine le type de machine de l'attaquant.
    Retourne : 'iot_device' | 'vps' | 'dedicated_server' | 'unknown'
    """
    tags = {t.lower() for t in host.get("tags", [])}

    if tags & _TAGS_IOT:
        return "iot_device"

    org = (host.get("org") or "").lower()
    isp = (host.get("isp") or "").lower()
    if any(v in org or v in isp for v in _ORGS_VPS):
        return "vps"

    if host.get("os"):
        return "dedicated_server"

    return "unknown"


def shodan_lookup(ip: str) -> dict:
    """
    Récupère les ports ouverts et vulnérabilités connues via Shodan InternetDB.
    Gratuit, sans clé API.
    Exemple : {"open_ports": [22, 80, 443], "vulns": ["CVE-2021-44228"]}
    """
    try:
        reponse = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=10
        )
        if reponse.status_code == 200:
            data = reponse.json()
            if "detail" in data:
                return {}  # IP inconnue de Shodan
            return {
                "open_ports": data.get("ports",     []),
                "vulns":      data.get("vulns",     []),
                "hostnames":  data.get("hostnames", []),
                "cpes":       data.get("cpes",      []),
                "tags":       data.get("tags",      []),
            }
        log.warning(f"InternetDB a retourné {reponse.status_code} pour {ip}")
    except Exception as e:
        log.warning(f"InternetDB échoué pour {ip} : {e}")
    return {}


# ══════════════════════════════════════════════════════════════════════════════
# 5. WHOIS / RDAP — informations réseau et organisation
# ══════════════════════════════════════════════════════════════════════════════

def whois_lookup(ip: str) -> dict:
    """
    Récupère les informations réseau de l'IP via RDAP (successeur de Whois).
    Exemple : {"org": "CHINANET jiangsu", "cidr": "222.186.0.0/16"}
    """
    try:
        from ipwhois import IPWhois
        resultat = IPWhois(ip).lookup_rdap(depth=1)
        reseau = resultat.get("network", {})
        return {
            "network": reseau.get("name", ""),
            "org":     resultat.get("asn_description", ""),
            "cidr":    reseau.get("cidr", ""),
        }
    except Exception as e:
        log.warning(f"Whois échoué pour {ip} : {e}")
    return {}


# ══════════════════════════════════════════════════════════════════════════════
# CLASSE PRINCIPALE — IPEnricher
# ══════════════════════════════════════════════════════════════════════════════

class IPEnricher:
    """
    Orchestre l'enrichissement complet d'une adresse IP.
    Gère le cache PostgreSQL pour éviter les appels API redondants.
    """

    # ── Cache PostgreSQL ───────────────────────────────────────────────────────

    def lire_cache(self, ip: str) -> Optional[dict]:
        """Retourne les données en cache si elles sont encore valides (< 24h)."""
        try:
            with connexion_postgres() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        "SELECT data FROM ip_enrichment_cache "
                        "WHERE ip = %s AND expires_at > NOW()",
                        (ip,)
                    )
                    ligne = cur.fetchone()
                    if ligne:
                        return ligne["data"]
        except Exception as e:
            log.warning(f"Lecture cache échouée pour {ip} : {e}")
        return None

    def ecrire_cache(self, ip: str, data: dict):
        """Sauvegarde les données enrichies dans le cache PostgreSQL."""
        expiration = maintenant_utc() + timedelta(hours=config.ENRICHMENT_CACHE_TTL_HOURS)
        try:
            with connexion_postgres() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO ip_enrichment_cache (ip, data, cached_at, expires_at)
                        VALUES (%s, %s, NOW(), %s)
                        ON CONFLICT (ip) DO UPDATE
                            SET data       = EXCLUDED.data,
                                cached_at  = NOW(),
                                expires_at = EXCLUDED.expires_at
                        """,
                        (ip, json.dumps(data), expiration)
                    )
                conn.commit()
        except Exception as e:
            log.warning(f"Écriture cache échouée pour {ip} : {e}")

    # ── Enrichissement d'une seule IP ──────────────────────────────────────────

    def enrichir(self, ip: str) -> dict:
        """
        Pipeline complet d'enrichissement pour une IP.

        Si l'IP est PRIVÉE → attaque interne, pas d'enrichissement externe.
        Si l'IP est PUBLIQUE → 5 sources d'enrichissement + mise en cache.
        """
        # ── Cas 1 : IP privée = attaque depuis l'intérieur du réseau ──────────
        if est_ip_privee(ip):
            log.warning(
                f"[MENACE INTERNE] L'attaque provient de l'intérieur du réseau "
                f"— IP source {ip} est privée"
            )
            return {
                "ip":           ip,
                "private":      True,
                "threat_origin": "internal",
                "note":         f"Attaque depuis l'intérieur du réseau (IP privée : {ip})",
            }

        # ── Cas 2 : IP publique — vérifier le cache d'abord ───────────────────
        cache = self.lire_cache(ip)
        if cache:
            log.debug(f"Cache hit pour {ip}")
            return cache

        log.info(f"Enrichissement de {ip} ...")

        # ── Pipeline d'enrichissement (5 sources) ─────────────────────────────
        geo            = geoip_lookup(ip)         # 1. Localisation (offline)
        anonymisation  = iplocate_lookup(ip)      # 2. Tor / VPN / Proxy
        reputation     = abuseipdb_lookup(ip)     # 3. Score AbuseIPDB
        infrastructure = shodan_lookup(ip)        # 4. Ports / vulns Shodan
        whois          = whois_lookup(ip)         # 5. Organisation / CIDR

        resultat = {
            "ip":             ip,
            "geo":            geo,
            "privacy":        anonymisation,
            "reputation":     reputation,
            "infrastructure": infrastructure,
            "whois":          whois,
            "enriched_at":    maintenant_utc().isoformat(),
        }

        # Sauvegarder en cache pour les prochains appels
        self.ecrire_cache(ip, resultat)
        return resultat

    # ── Enrichissement par lot ─────────────────────────────────────────────────

    def enrichir_lot(self, liste_ips: list) -> dict:
        """
        Enrichit une liste d'IPs. Ignore les doublons.
        Retourne un dictionnaire {ip: résultat}.
        """
        resultats = {}
        ips_uniques = list({ip for ip in liste_ips if ip})
        log.info(f"Enrichissement de {len(ips_uniques)} IPs uniques ...")
        for ip in ips_uniques:
            resultats[ip] = self.enrichir(ip)
        return resultats

    # ── Enrichissement depuis Elasticsearch ───────────────────────────────────

    # ── Alias (compatibilite avec l'ancien code et les tests) ─────────────────
    def enrich(self, ip: str) -> dict:
        return self.enrichir(ip)

    def enrich_batch(self, ips: list) -> dict:
        return self.enrichir_lot(ips)

    def check_cache(self, ip: str) -> Optional[dict]:
        return self.lire_cache(ip)

    def save_cache(self, ip: str, data: dict):
        return self.ecrire_cache(ip, data)

    def enrich_from_es(self, es_client, hours_back: int = 24) -> dict:
        return self.enrichir_depuis_es(es_client, hours_back)

    def enrichir_depuis_es(self, client_es, heures: int = 24) -> dict:
        """
        Récupère toutes les IPs source distinctes depuis Elasticsearch
        sur les N dernières heures, puis les enrichit.
        """
        depuis = (maintenant_utc() - timedelta(hours=heures)).isoformat()

        # Agrégation ES pour obtenir les IPs distinctes
        requete = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range":  {"@timestamp": {"gte": depuis}}},
                        {"exists": {"field": "source.ip"}}
                    ]
                }
            },
            "aggs": {
                "ips_distinctes": {
                    "terms": {"field": "source.ip.keyword", "size": 10000}
                }
            }
        }

        reponse = client_es.search(index=config.ES_INDEX, body=requete)
        ips = [b["key"] for b in reponse["aggregations"]["ips_distinctes"]["buckets"]]
        log.info(f"Trouvé {len(ips)} IPs source dans les dernières {heures}h")
        return self.enrichir_lot(ips)


# ── Alias publics (compatibilité avec les tests) ───────────────────────────────
_is_private      = est_ip_privee
_geoip_lookup    = geoip_lookup
_iplocate_lookup = iplocate_lookup
_abuseipdb_lookup = abuseipdb_lookup
_shodan_lookup   = shodan_lookup
_whois_lookup    = whois_lookup
_classify_machine = classifier_machine
