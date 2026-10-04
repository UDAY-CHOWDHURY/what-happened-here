import json, pathlib, uuid
from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import engine, ai

DATA = pathlib.Path(__file__).parent.parent / "data"
app = FastAPI(title="What Happened Here?")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
UPLOADS, INCIDENTS = {}, {}

def _store(text):
    ev = engine.normalize(engine.parse(text))
    uid = uuid.uuid4().hex[:8]
    UPLOADS[uid] = ev
    return {"id": uid, "count": len(ev), "preview": [e["raw_event"] for e in ev[:14]]}

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    try: return _store((await file.read()).decode())
    except Exception as e: raise HTTPException(400, f"Could not parse log file: {e}")

@app.post("/upload_sample/{name}")
def upload_sample(name: str):
    p = DATA / f"{name}.json"
    if not p.exists(): raise HTTPException(404, "Unknown sample")
    return _store(p.read_text())

class Analyze(BaseModel): id: str
class Explain(BaseModel): id: str; question: str | None = None

@app.post("/analyze")
def analyze(req: Analyze):
    if req.id not in UPLOADS: raise HTTPException(404, "Upload not found")
    inc = engine.analyze(UPLOADS[req.id]); inc["id"] = req.id
    INCIDENTS[req.id] = inc
    (DATA / "runs").mkdir(exist_ok=True)
    (DATA / "runs" / f"{req.id}.json").write_text(json.dumps(inc, indent=1))
    return inc

@app.get("/incident/{id}")
def incident(id: str):
    if id not in INCIDENTS: raise HTTPException(404, "Incident not found")
    return INCIDENTS[id]

@app.post("/explain")
def explain(req: Explain):
    if req.id not in INCIDENTS: raise HTTPException(404, "Analyze first")
    return ai.explain(INCIDENTS[req.id], req.question)
