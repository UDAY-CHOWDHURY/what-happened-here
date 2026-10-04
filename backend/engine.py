"""Parser + normalizer + deterministic correlation rules + prototype severity."""
import json, re

GOOD = {"chrome.exe", "outlook.exe", "explorer.exe", "teams.exe", "svchost.exe"}
SPINE = {"DOWNLOAD", "EXTRACT", "EXE_CREATE", "EXEC", "POWERSHELL", "CRED_ACCESS", "PRIV_ACTION"}
LABEL = {"DOWNLOAD": "Download", "EXTRACT": "Archive extracted", "EXE_CREATE": "Executable created",
         "EXEC": "Execution", "POWERSHELL": "PowerShell spawned", "EXT_CONN": "External connection",
         "MASS_ACCESS": "Mass file access", "MASS_MODIFY": "Mass file modification",
         "CRED_ACCESS": "Credential access", "PRIV_ACTION": "Privileged action"}
RULES = [  # id, name, from-tags, to-tags, why (all matched within 60s)
 ("R1", "Download → Executable creation", {"DOWNLOAD", "EXTRACT"}, {"EXE_CREATE"}, "A downloaded archive was followed by a new executable on disk."),
 ("R2", "Executable creation → Execution", {"EXE_CREATE"}, {"EXEC"}, "The newly created executable was run."),
 ("R3", "Execution → PowerShell", {"EXEC"}, {"POWERSHELL"}, "The executable spawned PowerShell, a common post-execution step."),
 ("R4", "Process activity → External connection", {"EXEC", "POWERSHELL", "CRED_ACCESS", "PRIV_ACTION"}, {"EXT_CONN"}, "A suspicious process contacted an external address."),
 ("R5", "Execution → Mass file access", {"EXEC", "POWERSHELL"}, {"MASS_ACCESS"}, "A suspicious process read an unusually large number of files."),
 ("R6", "Mass access → Mass modification", {"MASS_ACCESS"}, {"MASS_MODIFY"}, "Large-scale file reads were followed by large-scale writes."),
 ("R7", "Execution → Credential access", {"EXEC"}, {"CRED_ACCESS"}, "A suspicious process touched credential material."),
 ("R8", "Credential access → Privileged action", {"CRED_ACCESS"}, {"PRIV_ACTION"}, "Credential access was followed by a privileged change."),
]

def parse(text):
    text = text.strip()
    try:
        d = json.loads(text)
        return d["events"] if isinstance(d, dict) else d
    except json.JSONDecodeError:  # .log: one JSON object per line
        return [json.loads(l) for l in text.splitlines() if l.strip().startswith("{")]

def normalize(raw):
    out = []
    for i, r in enumerate(sorted(raw, key=lambda r: r.get("timestamp", ""))):
        out.append({"id": f"E{i+1}", "timestamp": r.get("timestamp"), "event_type": r.get("event_type", "UNKNOWN"),
                    "user": r.get("user"), "process": r.get("process"), "parent": r.get("parent"),
                    "source": r.get("source"), "destination": r.get("destination"), "file": r.get("file"),
                    "action": r.get("action"), "count": r.get("count", 1), "raw_event": r})
    return out

def secs(e):
    h, m, s = e["timestamp"][-8:].split(":")
    return int(h) * 3600 + int(m) * 60 + int(s)

def is_ext(ip):
    return bool(ip) and not ip.startswith(("10.", "192.168.", "127.")) and not re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip)

def tag(e):
    a, p, f = e["action"], (e["process"] or "").lower(), (e["file"] or "").lower()
    if a == "download": return "DOWNLOAD"
    if a == "extract": return "EXTRACT"
    if a == "create" and f.endswith((".exe", ".dll", ".scr")): return "EXE_CREATE"
    if a == "spawn" and "powershell" in p: return "POWERSHELL"
    if p in GOOD: return None  # known-good processes are treated as noise
    if a == "exec": return "EXEC"
    if a == "connect" and is_ext(e["destination"]): return "EXT_CONN"
    if a == "read" and e["count"] >= 10: return "MASS_ACCESS"
    if a == "write" and e["count"] >= 10: return "MASS_MODIFY"
    if a == "cred_access": return "CRED_ACCESS"
    if a == "priv": return "PRIV_ACTION"

def severity(t):
    if {"MASS_MODIFY", "EXT_CONN", "POWERSHELL"} <= t or {"CRED_ACCESS", "PRIV_ACTION", "EXT_CONN"} <= t \
       or {"EXEC", "MASS_ACCESS", "MASS_MODIFY"} <= t: return "CRITICAL"
    if "EXEC" in t and t & {"POWERSHELL", "CRED_ACCESS", "MASS_MODIFY", "EXT_CONN"}: return "HIGH"
    if "EXEC" in t: return "MEDIUM"
    return "LOW" if t else "NONE"

def build_graph(ch):
    nodes = [{"id": "user", "label": "User", "sub": ch[0]["user"] or "unknown", "kind": "user",
              "event_ids": [ch[0]["id"]], "x": 0, "y": 120}]
    edges, last, last_mass = [], "user", None
    for i, e in enumerate(ch, 1):
        t, nid = e["tag"], "n" + e["id"]
        sub = {"EXT_CONN": e["destination"], "MASS_ACCESS": f'{e["count"]} files', "MASS_MODIFY": f'{e["count"]} files'}.get(t) or e["file"] or e["process"]
        kind = "ext" if t == "EXT_CONN" else "mass" if t.startswith("MASS") else "proc"
        y = {"EXT_CONN": -20, "MASS_ACCESS": 250, "MASS_MODIFY": 250}.get(t, 120)
        nodes.append({"id": nid, "label": LABEL[t], "sub": sub, "kind": kind, "event_ids": [e["id"]], "x": i * 230, "y": y})
        edges.append({"id": f"e{i}", "source": last_mass if t == "MASS_MODIFY" and last_mass else last, "target": nid})
        if t in SPINE: last = nid
        if t == "MASS_ACCESS": last_mass = nid
    return nodes, edges

def analyze(events):
    for e in events: e["tag"] = tag(e)
    tg = [e for e in events if e["tag"]]
    findings = []
    for rid, name, A, B, why in RULES:
        for a in tg:
            b = next((b for b in tg if a["tag"] in A and b["tag"] in B and 0 <= secs(b) - secs(a) <= 60 and b is not a), None)
            if b:
                findings.append({"rule": rid, "name": name, "why": why, "event_ids": [a["id"], b["id"]]}); break
    ids = {i for f in findings for i in f["event_ids"]}
    if ids:  # pull in extraction steps that sit inside the chain's time span
        lo, hi = min(secs(e) for e in tg if e["id"] in ids), max(secs(e) for e in tg if e["id"] in ids)
        ids |= {e["id"] for e in tg if e["tag"] == "EXTRACT" and lo <= secs(e) <= hi}
    ch = [e for e in tg if e["id"] in ids]
    for i in range(len(ch)):  # R9: burst
        w = [e for e in ch[i:] if secs(e) - secs(ch[i]) <= 30]
        if len(w) >= 3:
            findings.append({"rule": "R9", "name": "Burst of suspicious events", "why": f"{len(w)} suspicious events occurred within {secs(w[-1]) - secs(w[0])}s.",
                             "event_ids": [e["id"] for e in w]}); break
    if not ch:
        return {"detected": False, "total_events": len(events), "chain": [], "findings": [], "severity": "NONE", "title": "No suspicious chain found", "nodes": [], "edges": []}
    tags = {e["tag"] for e in ch}
    title = "Credential Theft Chain" if "CRED_ACCESS" in tags else "Suspicious Execution Chain" if "POWERSHELL" in tags \
        else "Ransomware-like File Activity" if "MASS_MODIFY" in tags else "Suspicious Activity"
    nodes, edges = build_graph(ch)
    return {"detected": True, "total_events": len(events), "title": title, "severity": severity(tags),
            "chain": ch, "findings": findings, "nodes": nodes, "edges": edges,
            "note": "Prototype heuristic severity, not a validated risk score."}
