# Digital Twin OSINT — Public Footprint Visualizer

HackIndia team repository: CYBOZIST.

A consent-based public digital-footprint audit built for responsible OSINT education. The app searches indexed public web results, checks public GitHub profile metadata, and can optionally retrieve breach incident metadata for an email the user is authorized to check.

## What it does

- Live public web search via the Brave Search API when configured.
- Public GitHub profile candidates via GitHub's public API.
- Optional breach metadata via Have I Been Pwned API. It does not retrieve passwords or leaked dump contents.
- Evidence-first report with source links, timestamps, limitations, and print-to-PDF support.
- Privacy guardrails including authorization confirmation, basic rate limiting, and redaction of email addresses and phone-like strings from search snippets.

## Deploy for the hackathon

This repository includes a Render Blueprint (`render.yaml`) for deploying the FastAPI app.

1. Sign in to Render and choose New → Blueprint, then select this repository and apply `render.yaml`.
2. In the Render service environment settings, set `BRAVE_SEARCH_API_KEY` to a valid Brave Search API key. Keep the key in host secrets/environment settings, never in source code.
3. Optionally set `HIBP_API_KEY` if you have authorized access to the Have I Been Pwned account-search API.
4. Wait for deployment to finish, then open the service URL and confirm `/api/health` reports `ok: true` and `brave_configured: true`.

**Important:** GitHub stores the code; it does not run the Python backend. The app is not fully live until the backend is deployed and a valid search API key is configured. Render account authorization and API keys must be supplied by the project owner.

## Run locally

Requires Python 3.10+.

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux/Termux: source .venv/bin/activate
pip install -r backend/requirements.txt
cp backend/.env.example backend/.env
# Edit backend/.env and add BRAVE_SEARCH_API_KEY
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. Do not open `index.html` as a `file://` URL; the frontend calls the backend API.

## Responsible-use and limitations

- Only audit yourself or a person who explicitly authorized the audit.
- Search results may be stale, incomplete, or about another person with the same name.
- This tool does not search dark-web markets, scrape private social accounts, access private accounts, or collect private contact details.
- A missing result is not proof of no exposure. Results are not a certainty score.
- Query terms are sent to configured upstream providers. Review provider terms and privacy policies before a public demo.
- Before broad public release, add stronger shared rate limiting, monitoring, and a privacy notice.

See `backend/.env.example` for configuration. Never commit real API keys, passwords, or private data.
