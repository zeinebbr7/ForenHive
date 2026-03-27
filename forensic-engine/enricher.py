import os
import requests
import time
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

load_dotenv("/home/pfe/ForenHive/.env")

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
ES = Elasticsearch("http://localhost:9200")

def check_ip(ip):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5
        )
        if r.status_code == 200:
            d = r.json()["data"]
            return {
                "abuseScore":   d["abuseConfidenceScore"],
                "country":      d["countryCode"],
                "isp":          d["isp"],
                "totalReports": d["totalReports"],
                "domain":       d.get("domain", ""),
                "isTor":        d.get("isTor", False),
                "enriched":     True
            }
    except Exception as e:
        print(f"Erreur AbuseIPDB pour {ip}: {e}")
    return {"enriched": False}

def enrich_batch(index="honeypot-logs-2026.03.27", max_docs=50):
    query = {
        "query": {
            "bool": {
                "must": {"exists": {"field": "source.ip"}},
                "must_not": [
                    {"exists":  {"field": "abuseScore"}},
                    {"prefix":  {"source.ip": "10."}},
                    {"prefix":  {"source.ip": "172."}},
                    {"prefix":  {"source.ip": "192.168."}}
                ]
            }
        },
        "size": max_docs
    }

    resp = ES.search(index=index, body=query)
    hits = resp["hits"]["hits"]
    print(f"→ {len(hits)} documents à enrichir")

    seen_ips = {}
    for hit in hits:
        ip = hit["_source"].get("source.ip")
        if not ip:
            continue

        if ip not in seen_ips:
            print(f"  Checking {ip}...")
            seen_ips[ip] = check_ip(ip)
            time.sleep(1)

        enrichment = seen_ips[ip]
        if enrichment.get("enriched"):
            ES.update(index=hit["_index"], id=hit["_id"], body={"doc": enrichment})
            print(f"  ✅ {ip} → score={enrichment['abuseScore']} country={enrichment['country']} tor={enrichment['isTor']}")

if __name__ == "__main__":
    print("🔍 ForenHive Enrichment Engine — AbuseIPDB")
    enrich_batch()
