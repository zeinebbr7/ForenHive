import yara
import os
import hashlib
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv("/home/pfe/ForenHive/.env")

RULES_PATH = "/home/pfe/ForenHive/forensic-engine/yara-rules/malware.yar"
SAMPLES_DIR = "/home/pfe/ForenHive/malware-samples/binaries"
ES_URL = "http://localhost:9200"

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

def scan_file(path, rules):
    matches = rules.match(path)
    if matches:
        return [{"rule": m.rule, "description": m.meta.get("description", ""), "severity": m.meta.get("severity", "unknown")} for m in matches]
    return []

def scan_all():
    print("🔍 ForenHive YARA Scanner")
    rules = yara.compile(RULES_PATH)
    results = []
    for root, _, files in os.walk(SAMPLES_DIR):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                matches = scan_file(fpath, rules)
                entry = {
                    "file":      fname,
                    "path":      fpath,
                    "sha256":    sha256(fpath),
                    "timestamp": datetime.now().isoformat(),
                    "matches":   matches,
                    "infected":  len(matches) > 0
                }
                results.append(entry)
                if matches:
                    print(f"  🚨 {fname} → {[m['rule'] for m in matches]}")
                else:
                    print(f"  ✅ {fname} → clean")
            except Exception as e:
                print(f"  ❌ {fname} → erreur: {e}")
    print(f"\n📊 {len(results)} fichiers scannés, {sum(1 for r in results if r['infected'])} infectés")
    return results

def index_results(results):
    for r in results:
        if r["infected"]:
            resp = requests.post(
                f"{ES_URL}/forenhive-yara-scans/_doc",
                json=r,
                headers={"Content-Type": "application/json"}
            )
            if resp.status_code in (200, 201):
                print(f"  📥 Indexé: {r['file']} → {[m['rule'] for m in r['matches']]}")
            else:
                print(f"  ❌ Erreur: {resp.text}")

if __name__ == "__main__":
    results = scan_all()
    index_results(results)
