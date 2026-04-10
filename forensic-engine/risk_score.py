"""
ForenHive -- Calcul du Score de Risque
Attribue un score de 0 a 100 a chaque session d'attaque
en fonction de plusieurs indicateurs forensiques.

Grille de scoring :
  0-40  pts : Reputation IP (AbuseIPDB)
  0-10  pts : Anonymisation (Tor / VPN / Proxy)
  0-20  pts : Malware detecte par YARA
  0-15  pts : Detections VirusTotal
  0-10  pts : Volume de tentatives de connexion
  0-5   pts : Port cible critique (SMB, SQL, etc.)
  0-5   pts : Commandes executees (post-exploitation)
  0-5   pts : Volume de donnees exfiltrees
"""


# Ports critiques (bases de donnees, partage de fichiers, Docker...)
PORTS_CRITIQUES = {445, 1433, 27017, 3306, 5432, 6379, 2375, 9200}


def calculer_score_risque(session: dict) -> int:
    """
    Calcule le score de risque d'une session (0 = inoffensif, 100 = critique).

    Parametres attendus dans `session` :
      abuse_score     : score AbuseIPDB (0-100)
      is_tor          : bool
      is_vpn          : bool
      is_proxy        : bool
      yara_matches    : liste de noms de regles YARA
      vt_malicious    : nombre de moteurs VT ayant detecte un malware
      login_attempts  : nombre de tentatives de connexion
      destination_port: port cible
      command_count   : nombre de commandes executees (Cowrie)
      exfil_bytes     : octets transferes
    """
    score = 0

    # ── 1. Reputation IP via AbuseIPDB (0-40 pts) ──────────────────────────────
    # Un score AbuseIPDB de 100 = IP tres connue comme malveillante
    score_abuseipdb = int(session.get("abuse_score", 0))
    score += int(score_abuseipdb * 0.40)   # ex: 100 -> +40 pts

    # ── 2. Anonymisation : Tor / VPN / Proxy (0-10 pts) ───────────────────────
    # L'attaquant cache son identite = signal fort
    utilise_anonymiseur = (
        session.get("is_tor")   or
        session.get("is_vpn")   or
        session.get("is_proxy")
    )
    if utilise_anonymiseur:
        score += 10

    # ── 3. Malware detecte par YARA (0-20 pts) ────────────────────────────────
    regles_yara = session.get("yara_matches") or []
    if regles_yara:
        # Familles particulierement dangereuses
        familles_critiques = {"Mirai_Botnet", "WannaCry_Ransomware", "Emotet_Loader"}
        if any(r in familles_critiques for r in regles_yara):
            score += 20   # malware de haute severite
        else:
            score += 12   # autre malware

    # ── 4. Detections VirusTotal (0-15 pts) ───────────────────────────────────
    nb_detections_vt = int(session.get("vt_malicious", 0))
    if nb_detections_vt > 10:
        score += 15   # largement detecte (> 10 moteurs)
    elif nb_detections_vt > 0:
        score += 8    # quelques detections

    # ── 5. Volume de tentatives de connexion (0-10 pts) ───────────────────────
    nb_tentatives = int(session.get("login_attempts", 0))
    if nb_tentatives > 500:
        score += 10   # brute force massif
    elif nb_tentatives > 100:
        score += 5
    elif nb_tentatives > 10:
        score += 2

    # ── 6. Port cible critique (0-5 pts) ──────────────────────────────────────
    port = session.get("destination_port")
    if port and int(port) in PORTS_CRITIQUES:
        score += 5

    # ── 7. Commandes executees dans le shell (0-5 pts) ────────────────────────
    # Plus de commandes = l'attaquant est alle loin (post-exploitation)
    nb_commandes = int(session.get("command_count", 0))
    if nb_commandes > 20:
        score += 5
    elif nb_commandes > 5:
        score += 2

    # ── 8. Volume d'exfiltration (0-5 pts) ────────────────────────────────────
    octets_exfiltres = int(session.get("exfil_bytes", 0))
    if octets_exfiltres > 1_000_000:   # > 1 Mo
        score += 5
    elif octets_exfiltres > 100_000:   # > 100 Ko
        score += 2

    # Le score est toujours compris entre 0 et 100
    return min(score, 100)


def niveau_risque(score: int) -> str:
    """Convertit un score numerique en niveau lisible."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "INFO"


# Alias (compatibilite avec l'ancien code)
calculate_risk_score = calculer_score_risque
risk_level           = niveau_risque
