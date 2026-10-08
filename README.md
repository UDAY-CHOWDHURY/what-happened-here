# What Happened Here?

AI-assisted incident reconstruction prototype that analyzes synthetic system and security events, correlates related activities, and reconstructs them into an understandable incident timeline and event graph.

It identifies activities such as file downloads, process execution, privilege changes, network connections, and file modifications, then uses AI to explain why the sequence may be suspicious and what should be investigated next.

> **Note:** Synthetic data only; severity is a prototype heuristic.

## How It Works

```text
Synthetic System & Security Events
              │
              ▼
        Event Processing
              │
              ▼
       Event Correlation
              │
              ▼
      Incident Reconstruction
          ┌────┴────┐
          ▼         ▼
      Timeline   Event Graph
          │         │
          └────┬────┘
               ▼
      Suspicious Activity
          Analysis
               │
               ▼
       AI Explanation
               │
               ▼
     Investigation Story
```

## Run

```bash
pip install -r requirements.txt && python data/gen_data.py
cd backend && uvicorn main:app --port 8000
cd frontend && npm install && npm run dev      # http://localhost:5173
ollama pull llama3.1 && ollama serve           # optional; falls back to rule-based text (OLLAMA_MODEL to change)
```
