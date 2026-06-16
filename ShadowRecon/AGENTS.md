# ShadowRecon — Build & Run Instructions

## Prerequisites
- Python 3.10+
- Node.js 20+ (for frontend dev)
- Ollama (optional, for LLM features)

## Setup

### Python Backend
```bash
cd ShadowRecon
pip install -r requirements.txt
```

### Vue Frontend (development)
```bash
cd web/frontend
npm install
npm run dev     # starts Vite dev server on :5173
```

### Production Build
```bash
cd web/frontend
npm run build   # outputs to web/frontend/dist
# FastAPI will serve the static files
```

## Run

### Web UI (recommended)
```bash
python main.py --web
# Opens at http://localhost:8000
```

### CLI Scan
```bash
python main.py --url https://example.com --campaign "Pentest Week"
python main.py --url https://example.com --llm               # with LLM enrichment
python main.py --url https://example.com --confirm --threads 50  # confirmation mode
python main.py --web --llm                                   # web UI with LLM
```

## LLM Configuration
Edit `core/config.py` or set env vars:
- LLM host: `http://192.168.50.228:11434` (default)
- Model: `RedQueen` (default)
- Enable in UI: toggle "Enable LLM Analysis" in scan form

## Project Structure
```
ShadowRecon/
├── core/          # Engine, config, DB, dedup, models
├── scanners/      # API, directory, misconfig, WAF, anomaly
├── llm/           # Ollama/OpenAI provider + enhancer
├── mapping/       # NetworkX graph + mapper
├── reporting/     # HTML/JSON report generation
├── exporters/     # JSONL training data export
├── web/
│   ├── backend/   # FastAPI server
│   └── frontend/  # Vue 3 + Vite + D3.js
├── data/
│   ├── wordlists/ # API paths, directories, probes
│   └── signatures/ # WAF fingerprints
├── main.py        # Entry point
├── setup.py
└── requirements.txt
```

## Adding a New Scanner
1. Create `scanners/your_scanner.py`
2. Create class extending `BaseScanner` with `name` property
3. Decorate with `@register_scanner`
4. Implement `async def scan(self, target) -> (list[Finding], list[Endpoint])`
5. Scanner auto-registers and runs with the engine

## Adding WAF Signatures
Edit `data/signatures/waf_signatures.yaml` and add an entry following the existing format.

## Extending Wordlists
Edit files in `data/wordlists/` — one entry per line, `#` for comments.

## Export Training Data
```bash
# Via API:
curl http://localhost:8000/api/export/training-data/{campaign_id} -o training.jsonl
```
