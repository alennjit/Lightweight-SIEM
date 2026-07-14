# Lightweight SIEM

A subscription protection service for non-technical people — most often
parents or grandparents — who are frequent targets of phishing email and
scam links. A family member (the **monitor**) gets a real-time alert the
moment a risky message shows up, so they can step in before money,
credentials, or personal data are lost.

This is **not** a traditional enterprise SIEM. It's a small, focused
detection + alerting pipeline built for one household relationship: one
protected person, one or more monitors.

> Status: the heuristic detection engine, a minimal scoring API, and a
> working dashboard are built and verified running end to end locally.
> Nothing is deployed or handling real user data yet. See
> [docs/ROADMAP.md](docs/ROADMAP.md) for sequencing.

---

## How It Works (target v1)

1. The **protected person** connects their email account (Gmail or Outlook)
   via OAuth and installs a browser extension.
2. Incoming email is scanned for phishing indicators (spoofed sender
   domains, suspicious links, urgency/credential-harvesting language).
   Flagged link visits from the browser extension are also caught in
   real time, before the page loads.
3. When something is flagged, the **monitor** (a linked family member) gets
   an alert via their chosen channel — push, SMS, or email — with a
   plain-language explanation of the risk.
4. The monitor can check a web dashboard for history and current status.

SMS/text-message monitoring is **not** in v1 — see
[docs/ROADMAP.md](docs/ROADMAP.md) for why and when.

---

## Features

Status legend: ✅ done · 🚧 in progress · 📋 planned · ⏸️ deferred (not v1)

| Feature | Status | Notes |
|---|---|---|
| Project scaffold (CLAUDE.md, docs, folder structure) | ✅ | |
| Phishing heuristic scoring engine | ✅ | `backend/app/detection/heuristics.py` — sender/link brand impersonation, IP-literal and punycode links, URL shorteners, abused TLDs, urgency/credential-harvesting language, free-webmail-claiming-to-be-a-bank. 13 unit tests. |
| Email-scoring API + Alert persistence | ✅ | `POST /api/v1/emails/score`, `GET /api/v1/alerts` — SQLAlchemy models, SQLite for dev. 3 integration tests. |
| Monitor web dashboard (React + TypeScript + Vite) | ✅ | `dashboard/` — alert list + a "test the detection engine" form wired to the live API. Verified end to end in a real browser (see `.claude/skills/run-lightweight-siem/`). |
| Email OAuth integration (Gmail) | 📋 | `backend/app/integrations/gmail_client.py` — needs real OAuth credentials, not yet started |
| Email OAuth integration (Outlook/Microsoft Graph) | 📋 | `backend/app/integrations/outlook_client.py` |
| URL/link reputation checking (external threat intel) | 📋 | Threat intel source TBD — VirusTotal / PhishTank / Safe Browsing. Local URL heuristics (no external calls) already live in the scoring engine above. |
| Claude-generated risk narrative | 📋 | Only invoked after a heuristic flag, per privacy design |
| Browser extension (Chrome/Edge, Manifest V3) | 📋 | `browser-extension/` — manifest + stubs only, no logic yet |
| Monitor ↔ protected-person account linking | 📋 | Invite/consent flow, requires auth (not built) |
| Alerting: push notifications | 📋 | |
| Alerting: SMS (Twilio) | 📋 | |
| Alerting: email | 📋 | |
| Subscription billing | 📋 | Stripe assumed, not confirmed |
| Native mobile app (Android) | ⏸️ | Phase 2 — device-level notification + SMS scanning |
| Native mobile app (iOS) | ⏸️ | Phase 2+ — no SMS access on iOS; app would cover email/browser only unless Apple opens new APIs |
| SMS/smishing detection | ⏸️ | Deferred — see ROADMAP for rationale |

This table is updated as work lands — treat it as the source of truth for
what's actually built versus what's aspirational.

---

## Why No SMS in v1

iOS gives third-party apps no API to read incoming text messages, and
Android requires an intrusive SMS-reader permission that would need its own
trust-building UX. Shipping a credible, working product on email + browser
protection first — where OAuth and Manifest V3 give clean, well-supported
integration points on every platform — was chosen over a fragmented,
Android-only SMS feature that would confuse the "works for everyone"
pitch of the product. SMS support is tracked as a deliberate phase 2+ item.

---

## Privacy Posture

This product reads another adult's email on their behalf, for their own
protection. That only works ethically and legally with informed consent
from the protected person and tight data-minimization limits on what the
monitor can actually see. Full detail lives in
[docs/PRIVACY_AND_CONSENT.md](docs/PRIVACY_AND_CONSENT.md) — read it before
touching any ingestion or storage code.

---

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full breakdown.
Short version:

```
protected person's inbox (Gmail/Outlook OAuth)
        │
        ▼
   backend (FastAPI) ── detection (heuristics + Claude narrative)
        │                       │
        ▼                       ▼
  alert dispatch          web dashboard (monitor)
   (push/SMS/email)
```

Browser extension talks directly to the backend's link-reputation API to
block/warn on malicious links at click time, independent of the email path.

---

## Repository Structure

```
Lightweight-SIEM/
├── CLAUDE.md                    ← full project context for Claude Code
├── README.md                    ← you are here
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PRIVACY_AND_CONSENT.md
│   └── ROADMAP.md
├── backend/                     ← FastAPI service
├── browser-extension/           ← Manifest V3 extension
├── dashboard/                   ← monitor web dashboard (frontend, TBD framework)
└── mobile-app/                  ← phase 2 placeholder, empty for now
```

---

## Getting Started

### Backend

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
pytest -v                     # 16 tests as of this writing
```

Requires environment variables — see `backend/.env.example` once secrets
integrations land. Never commit a real `.env` file; this is a public repo.
Uses SQLite (`dev.db`, gitignored) for local dev — swappable via
`DATABASE_URL`.

### Dashboard

```bash
cd dashboard
npm install
npm run dev        # http://localhost:5173, expects the backend on :8000
```

CORS is already configured on the backend for `localhost:5173`.

---

## Tech Stack

- **Backend**: Python 3.11+, FastAPI
- **Detection**: rule-based heuristics + Claude API for risk narratives
- **Browser extension**: Manifest V3 (Chrome/Edge)
- **Dashboard**: React + TypeScript + Vite
- **Billing**: Stripe (assumed, not yet confirmed)
- **Alerting**: Twilio (SMS), web push, transactional email

---

## License

MIT — see [LICENSE](LICENSE).
