import os
import json
from pathlib import Path
from datetime import datetime
import chromadb
from chromadb.utils import embedding_functions

COLLECTION_NAME = "rca_incidents"
EMBED_MODEL     = "all-MiniLM-L6-v2"


def _get_collection(persist_dir: str = "./rca_memory"):
    client = chromadb.PersistentClient(path=persist_dir)
    ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBED_MODEL
    )
    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"}
    )


def search_similar(
    findings_text: str,
    n_results: int = 3,
    persist_dir: str = "./rca_memory"
) -> list[str]:
    collection = _get_collection(persist_dir)
    count = collection.count()
    if count == 0:
        print("[chromadb] Empty — no past incidents yet")
        return []
    results = collection.query(
        query_texts=[findings_text],
        n_results=min(n_results, count)
    )
    incidents = []
    docs  = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    for doc, meta in zip(docs, metas):
        root_cause  = meta.get("root_cause", "unknown")
        remediation = meta.get("remediation", "unknown")
        date        = meta.get("date", "unknown")
        incidents.append(
            f"[{date}] Root cause: {root_cause} | "
            f"Fix: {remediation}"
        )
        print(f"[chromadb] Match: {root_cause[:60]}...")
    return incidents


def save_incident(
    findings_text: str,
    root_cause:    str,
    remediation:   str,
    severity:      str = "medium",
    session_id:    str = None,
    persist_dir:   str = "./rca_memory"
) -> bool:
    try:
        collection = _get_collection(persist_dir)
        doc_id = session_id or datetime.utcnow().strftime(
            "%Y%m%d_%H%M%S"
        )
        collection.upsert(
            ids=[doc_id],
            documents=[findings_text],
            metadatas=[{
                "root_cause":  root_cause[:500],
                "remediation": remediation[:500],
                "severity":    severity,
                "date": datetime.utcnow().strftime("%Y-%m-%d"),
            }]
        )
        print(f"[chromadb] Saved: {doc_id}")
        return True
    except Exception as e:
        print(f"[chromadb] Save failed: {e}")
        return False


def seed_with_examples(persist_dir: str = "./rca_memory"):
    examples = [
        {
            "id": "INC-001",
            "text": "Brute force attack RDP 847 failed logins single IP 2 minutes EID=4625 high volume followed by successful login EID=4624",
            "root_cause": "Compromised contractor IP used for automated RDP brute force against admin account",
            "remediation": "Block IP range rotate credentials enable MFA on RDP",
            "severity": "critical",
        },
        {
            "id": "INC-002",
            "text": "SQL injection succeeded login endpoint UNION SELECT URI status 200 WAF sql_injection confidence 0.9",
            "root_cause": "Unsanitized input login endpoint allowed SQL injection bypassing authentication",
            "remediation": "Parameterized queries deploy WAF rules rotate database credentials",
            "severity": "critical",
        },
        {
            "id": "INC-003",
            "text": "Directory traversal etc passwd succeeded GET ../../../../etc/passwd status 200 sensitive file access confirmed",
            "root_cause": "Missing path sanitization allowed directory traversal to read system files",
            "remediation": "Sanitize file path inputs implement chroot jail update web server config",
            "severity": "critical",
        },
        {
            "id": "INC-004",
            "text": "Privilege escalation after initial access EID=4672 admin privileges assigned EID=4648 explicit credential use T1078",
            "root_cause": "Attacker used valid credentials to assign admin privileges to compromised account",
            "remediation": "Review privilege assignments implement least privilege enable audit logging",
            "severity": "high",
        },
        {
            "id": "INC-005",
            "text": "XSS attack web application script alert document cookie URI status 200 attack succeeded",
            "root_cause": "Reflected XSS search parameter allowed script injection",
            "remediation": "Implement CSP headers sanitize outputs HttpOnly cookies WAF XSS rules",
            "severity": "high",
        },
    ]
    collection = _get_collection(persist_dir)
    if collection.count() >= len(examples):
        print(f"[chromadb] Already seeded ({collection.count()} incidents)")
        return
    for ex in examples:
        collection.upsert(
            ids=[ex["id"]],
            documents=[ex["text"]],
            metadatas=[{
                "root_cause":  ex["root_cause"],
                "remediation": ex["remediation"],
                "severity":    ex["severity"],
                "date":        "2024-01-01",
            }]
        )
    print(f"[chromadb] Seeded {len(examples)} incidents")


def build_findings_text(templates: list, sigma_hits: list) -> str:
    parts = []
    critical = [t for t in templates
                if t.get("top_severity") == "critical"]
    high = [t for t in templates
            if t.get("top_severity") == "high"]
    if critical:
        parts.append(f"{len(critical)} critical patterns")
    if high:
        parts.append(f"{len(high)} high severity patterns")
    attacks = set()
    for t in templates:
        attacks.update(t.get("attack_types", []))
    if attacks:
        parts.append(f"attacks: {', '.join(attacks)}")
    for h in sigma_hits[:3]:
        parts.append(
            f"Sigma: {h['rule_name']} ({h['technique']})"
        )
    return ". ".join(parts) if parts else \
           "No significant findings detected"


if __name__ == "__main__":
    import sys
    sys.path.insert(
        0, str(Path(__file__).resolve().parents[1])
    )

    print("=== ChromaDB Store Test ===\n")
    print("Step 1: Seeding with 5 example incidents...")
    seed_with_examples()

    findings = (
        "WAF sql_injection directory_traversal xss. "
        "EID=4672 admin privilege 713 events high. "
        "EID=4648 explicit credentials 75 events. "
        "T1531 User Logoff confirmed by Sigma."
    )

    print("\nStep 2: Searching similar incidents...")
    matches = search_similar(findings)
    print(f"\nFound {len(matches)} similar incidents:")
    for m in matches:
        print(f"  {m}")

    print("\nStep 3: Saving test incident...")
    save_incident(
        findings_text=findings,
        root_cause="Normal Windows activity with WAF attacks",
        remediation="No immediate action required",
        severity="medium",
        session_id="test_001"
    )

    print("\nStep 4: Collection count:")
    col = _get_collection()
    print(f"  Total incidents stored: {col.count()}")
    print("\n=== ChromaDB Test Complete ===")
