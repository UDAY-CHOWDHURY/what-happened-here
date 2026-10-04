# What Happened Here?
AI-assisted incident reconstruction prototype (synthetic data only; severity is a prototype heuristic).

    pip install -r requirements.txt && python data/gen_data.py
    cd backend && uvicorn main:app --port 8000
    cd frontend && npm install && npm run dev      # http://localhost:5173
    ollama pull llama3.1 && ollama serve           # optional; falls back to rule-based text (OLLAMA_MODEL to change)
