"""Generates SYNTHETIC incident logs. Nothing here is real malware or a real connection."""
import json, random, pathlib
random.seed(7)
GOOD = ["chrome.exe", "outlook.exe", "explorer.exe", "teams.exe", "svchost.exe"]
def ts(s): return f"{s//3600:02d}:{s%3600//60:02d}:{s%60:02d}"
def ev(t, typ, proc, act, **k): return {"timestamp": t, "event_type": typ, "user": "alice", "process": proc, "action": act, **k}
def noise(n, t0, span):
    out = []
    for _ in range(n):
        a = random.choice(["read", "write", "connect", "read", "connect"]); p = random.choice(GOOD)
        if a == "connect":
            out.append(ev(ts(t0 + random.randrange(span)), "NETWORK_EVENT", p, a, source="10.0.0.23", destination=random.choice(["10.0.0.5", "142.250.77.14", "52.96.12.3"])))
        else:
            out.append(ev(ts(t0 + random.randrange(span)), "FILE_EVENT", p, a, file=random.choice(["report.docx", "notes.txt", "budget.xlsx", "inbox.pst"]), count=random.randint(1, 4)))
    return out
H = lambda h, m, s: h * 3600 + m * 60 + s
inc1 = [ev("10:31:02", "USER_ACTION", "chrome.exe", "download", file="update.zip"),
        ev("10:31:08", "FILE_EVENT", "explorer.exe", "extract", file="update.zip"),
        ev("10:31:11", "FILE_EVENT", "explorer.exe", "create", file="update.exe"),
        ev("10:31:13", "PROCESS_EVENT", "update.exe", "exec", file="update.exe"),
        ev("10:31:15", "PROCESS_EVENT", "powershell.exe", "spawn", parent="update.exe"),
        ev("10:31:20", "NETWORK_EVENT", "powershell.exe", "connect", source="10.0.0.23", destination="185.XX.XX.10"),
        ev("10:31:25", "FILE_EVENT", "powershell.exe", "read", count=42),
        ev("10:31:29", "FILE_EVENT", "powershell.exe", "write", count=18)]
inc2 = [ev("14:02:10", "PROCESS_EVENT", "procdump.exe", "exec", file="procdump.exe"),
        ev("14:02:14", "FILE_EVENT", "procdump.exe", "cred_access", file="lsass.exe memory"),
        ev("14:02:19", "PROCESS_EVENT", "procdump.exe", "priv", detail="Added account to Administrators"),
        ev("14:02:26", "NETWORK_EVENT", "procdump.exe", "connect", source="10.0.0.23", destination="91.XX.XX.44")]
inc3 = [ev("16:20:00", "PROCESS_EVENT", "svc_updater.exe", "exec", file="svc_updater.exe"),
        ev("16:20:03", "FILE_EVENT", "svc_updater.exe", "read", count=640),
        ev("16:20:09", "FILE_EVENT", "svc_updater.exe", "write", count=612)]
here = pathlib.Path(__file__).parent
for name, chain, n, t0 in [("incident_01", inc1, 119, H(9, 0, 0)), ("incident_02", inc2, 116, H(13, 0, 0)), ("incident_03", inc3, 120, H(15, 0, 0))]:
    evs = noise(n, t0, 7200) + chain; random.shuffle(evs)
    (here / f"{name}.json").write_text(json.dumps({"events": evs}, indent=1))
    print(name, len(evs))
