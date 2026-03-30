import os
import json
import requests
from datetime import datetime
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

load_dotenv("/home/pfe/ForenHive/.env")

ES = Elasticsearch("http://localhost:9200")
OLLAMA_URL = "http://localhost:11434/api/generate"

PROMPT_TEMPLATE = """Tu es un expert en cybersécurité spécialisé dans le framework MITRE ATT&CK.

Contexte des honeypots:
- cowrie: honeypot SSH/Telnet — capture brute-force, login/password, commandes shell
- dionaea: honeypot SMB/MySQL/MSSQL — capture exploits réseau et malwares
- galah: honeypot HTTP — capture injections SQL, path traversal, scans web
- zeek: analyseur réseau passif — capture tout le trafic réseau

Analyse cet événement et identifie la tactique et technique MITRE ATT&CK EXACTE.

Exemples de mappings corrects:
- SSH brute-force cowrie → TA0006 Credential Access / T1110 Brute Force
- SMB exploit dionaea → TA0008 Lateral Movement / T1210 Exploitation of Remote Services
- SQL injection galah → TA0001 Initial Access / T1190 Exploit Public-Facing Application
- Network scan zeek → TA0043 Reconnaissance / T1595 Active Scanning
- Commande wget/curl cowrie → TA0011 Command and Control / T1105 Ingress Tool Transfer

Événement à analyser:
{event}

Réponds UNIQUEMENT en JSON valide, sans texte avant ou après:
{{
  "tactic": "nom exact de la tactique MITRE",
  "tactic_id": "TAXXXX",
  "technique": "nom exact de la technique MITRE",
  "technique_id": "TXXXX",
  "confidence": "high/medium/low",
  "explanation": "explication courte en français"
}}"""

def query_mistral(event: dict) -> dict:
    event_str = json.dumps(event, ensure_ascii=False, indent=2)
    prompt = PROMPT_TEMPLATE.format(event=event_str)
    
    try:
        r = requests.post(
            OLLAMA_URL,
            json={
                "model": "mistral",
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1}
            },
            timeout=120
        )
        if r.status_code == 200:
            response_text = r.json().get("response", "")
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(response_text[start:end])
    except Exception as e:
        print(f"  ❌ Erreur Ollama: {e}")
    return {}

def map_mitre(index=None, max_docs=10):
    print("🧠 ForenHive MITRE ATT&CK Mapper — Ollama/Mistral")
    
    from datetime import datetime as dt, timedelta
    if index is None:
        import requests as req
        r = req.get("http://localhost:9200/_cat/indices/honeypot-logs-*?h=index&s=index:desc")
        indices = [line.strip() for line in r.text.strip().split("\n") if line.strip()]
        index = indices[0] if indices else f"honeypot-logs-{dt.now().strftime('%Y.%m.%d')}"
        print(f"  Index utilisé: {index}")
    
    resp = ES.search(index=index, body={
        "size": max_docs,
        "query": {
            "bool": {
                "must": [
                    {"exists": {"field": "honeypot.type"}},
                    {"exists": {"field": "source.ip"}}
                ],
                "must_not": [
                    {"exists": {"field": "mitre_mapped"}},
                    {"term": {"honeypot.type.keyword": "zeek"}}
                ]
            }
        },
        "_source": ["honeypot.type", "source.ip", "event.id",
                   "user.name", "user.password", "http.request.uri",
                   "http.request.method", "abuseScore", "country",
                   "dionaea.msg"]
    })

    hits = resp["hits"]["hits"]
    print(f"→ {len(hits)} événements à analyser")

    for hit in hits:
        event = hit["_source"]
        print(f"\n  Analyse: {event.get('honeypot.type')} — {event.get('source.ip')}")
        
        mitre = query_mistral(event)
        
        if mitre:
            doc = {
                "@timestamp":   datetime.now().isoformat(),
                "event":        event,
                "tactic":       mitre.get("tactic", ""),
                "tactic_id":    mitre.get("tactic_id", ""),
                "technique":    mitre.get("technique", ""),
                "technique_id": mitre.get("technique_id", ""),
                "confidence":   mitre.get("confidence", ""),
                "explanation":  mitre.get("explanation", ""),
                "source_index": hit["_index"],
                "source_id":    hit["_id"],
                "mitre_mapped": True
            }
            ES.index(index=f"forenhive-mitre-{dt.now().strftime('%Y.%m.%d')}", body=doc)
            print(f"  ✅ {mitre.get('tactic_id')} — {mitre.get('technique_id')}: {mitre.get('technique')}")
            print(f"     Confiance: {mitre.get('confidence')} | {mitre.get('explanation')}")
        else:
            print(f"  ⚠️  Pas de mapping trouvé")

if __name__ == "__main__":
    map_mitre()
