import os
import requests
import time
from dotenv import load_dotenv

load_dotenv("/home/pfe/ForenHive/.env")

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ES_URL = "http://localhost:9200"

def check_hash(sha256):
    """Interroge VirusTotal pour un hash SHA256"""
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": VT_KEY},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "vt_malicious":   stats.get("malicious", 0),
                "vt_suspicious":  stats.get("suspicious", 0),
                "vt_harmless":    stats.get("harmless", 0),
                "vt_total":       sum(stats.values()),
                "vt_name":        data.get("meaningful_name", ""),
                "vt_type":        data.get("type_description", ""),
                "vt_checked":     True
            }
        elif r.status_code == 404:
            print(f"  ⚠️  Hash inconnu de VirusTotal")
            return {"vt_checked": False, "vt_reason": "unknown"}
        else:
            print(f"  ❌ Erreur VT: {r.status_code}")
            return {"vt_checked": False}
    except Exception as e:
        print(f"  ❌ Exception: {e}")
        return {"vt_checked": False}

def enrich_yara_results():
    """Enrichit les résultats YARA avec VirusTotal"""
    print("🔍 ForenHive VirusTotal Scanner")

    # Récupère les scans YARA non encore enrichis par VT
    resp = requests.post(
        f"{ES_URL}/forenhive-yara-scans/_search",
        json={
            "query": {
                "bool": {
                    "must":     {"term": {"infected": True}},
                    "must_not": {"exists": {"field": "vt_checked"}}
                }
            },
            "size": 10
        },
        headers={"Content-Type": "application/json"}
    )

    hits = resp.json()["hits"]["hits"]
    print(f"→ {len(hits)} fichiers à analyser")

    for hit in hits:
        sha256 = hit["_source"].get("sha256")
        fname  = hit["_source"].get("file")
        print(f"  Checking {fname} ({sha256[:16]}...)...")

        vt_result = check_hash(sha256)
        time.sleep(15)  # Rate limit VT gratuit : 4 req/min

        # Met à jour le document dans ES
        requests.post(
            f"{ES_URL}/forenhive-yara-scans/_update/{hit['_id']}",
            json={"doc": vt_result},
            headers={"Content-Type": "application/json"}
        )

        if vt_result.get("vt_checked"):
            print(f"  ✅ {fname} → {vt_result['vt_malicious']}/{vt_result['vt_total']} antivirus détectent")
        
if __name__ == "__main__":
    enrich_yara_results()
