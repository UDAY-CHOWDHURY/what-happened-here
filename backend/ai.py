import json, os, requests
OLLAMA = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

def _fallback(inc, q, err):
    f = inc["findings"]
    return {"source": "rule-based fallback (Ollama unavailable)", "error": err,
            "summary": f'{inc["title"]}: {len(inc["chain"])} of {inc["total_events"]} events form a suspicious chain (severity {inc["severity"]}).',
            "suspicious": " ".join(x["why"] for x in f),
            "evidence": [{"claim": x["why"], "event_ids": x["event_ids"]} for x in f],
            "recommendations": ["Investigate the executable/process that started the chain", "Inspect any external destination address",
                                "Check affected files and accounts", "Review the user's recent activity",
                                "Consider isolating the endpoint if confirmed malicious"],
            "answer": " ".join(x["why"] for x in f) if q else ""}

def explain(inc, question=None):
    ids = {e["id"] for e in inc["chain"]}
    ctx = [{k: e[k] for k in ("id", "timestamp", "event_type", "user", "process", "parent", "destination", "file", "action", "count")} for e in inc["chain"]]
    prompt = ("You are assisting a SOC analyst. Use ONLY the events below; never invent evidence; cite event ids. "
              "This is a prototype heuristic, do not claim certainty.\n"
              f"Incident: {inc['title']} (heuristic severity {inc['severity']})\nEvents: {json.dumps(ctx)}\nRule findings: {json.dumps(inc['findings'])}\n"
              f"Analyst question: {question or 'none'}\n"
              'Reply as JSON: {"summary": str, "suspicious": str, "evidence": [{"claim": str, "event_ids": [str]}], "recommendations": [str], "answer": str}')
    try:
        r = requests.post(f"{OLLAMA}/api/generate", json={"model": MODEL, "prompt": prompt, "stream": False, "format": "json"}, timeout=120)
        d = json.loads(r.json()["response"])
        d["evidence"] = [{"claim": str(x.get("claim", "")), "event_ids": [i for i in x.get("event_ids", []) if i in ids]}
                         for x in d.get("evidence", []) if isinstance(x, dict)]
        d["source"] = f"ollama:{MODEL}"
        return d
    except Exception as e:
        return _fallback(inc, question, str(e))
