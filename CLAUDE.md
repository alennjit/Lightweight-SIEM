# CLAUDE.md — Lightweight SIEM

Project-specific context for Claude Code. This extends (does not replace) the
global `~/CLAUDE.md` conventions — Python type hints, `pathlib`, `logging`
over `print`, secrets from env vars only, `subprocess.run(shell=False)` only,
pytest with mocked external calls, explicit over clever.

---

## What This Is

A subscription SIEM/protection product for non-technical people (commonly
parents/grandparents) who are frequent targets of phishing email and smishing
(fake text) scams. A tech-savvy family member ("the monitor") gets real-time
alerts when the protected person receives — or worse, interacts with — a
malicious email or link, so they can intervene before money or credentials
are lost.

This is an Alen Frash / Diamond Technologies LLC side product, not an MSP
client deliverable. Public repo — this doubles as a portfolio piece, so
**never commit real client data, real detection signatures tied to MSP
clients, or any secret/API key.**

---

## Scope Decisions (locked in — revisit deliberately, don't silently drift)

- **v1 covers email + browser only. No SMS/text monitoring in v1.**
  Reason: iOS provides no third-party API for reading incoming SMS; building
  Android-only SMS support first would fragment the protected-person
  experience before the core product is proven. SMS support is a tracked
  v2+ item (see `docs/ROADMAP.md`), likely Android-only via SMS Retriever,
  or a forwarding-based workaround for iOS.
- **Delivery is phased**: browser extension (Chrome/Edge, Manifest V3) +
  email OAuth integration (Gmail API, Microsoft Graph) ship first. A native
  mobile app (Android first) is a phase 2 build for full-device coverage
  (notification scanning, SMS).
- **Monitor experience**: web dashboard (history, link status, account
  management) + real-time alerts. Alert channel is the monitor's choice at
  signup: push (web push), SMS (Twilio), or email (SES/SendGrid).
- **Backend**: Python (FastAPI). Matches the conventions and mental model
  already established in the Shadow IT Scanner project — reuse that
  project's pattern of an `ai/claude_client.py`-style wrapper with prompts
  as named constants, not inline strings.
- **Repo**: public on GitHub, named `Lightweight-SIEM`.

## Not Yet Decided

- Frontend framework for the dashboard (leaning React + TypeScript + Vite —
  confirm before investing heavily).
- Hosting target for the backend (candidate: same NemoClaw self-hosted
  server used for Shadow IT Scanner, vs. a managed cloud host — matters once
  this needs to be reliable for paying subscribers with uptime expectations).
- Billing provider — assume Stripe unless told otherwise.
- URL/threat intel source(s) for link reputation — candidates: VirusTotal,
  PhishTank, Google Safe Browsing API. Needs a decision that accounts for
  free-tier rate limits at subscriber scale.

---

## Architecture (target shape)

```
Lightweight-SIEM/
├── CLAUDE.md
├── README.md                    ← feature list + status, kept current every session
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PRIVACY_AND_CONSENT.md   ← non-negotiable: read before touching ingestion code
│   └── ROADMAP.md
├── backend/
│   ├── app/
│   │   ├── main.py              ← FastAPI app entry
│   │   ├── core/                ← config (env-var loading), security, logging setup
│   │   ├── detection/           ← heuristics.py, claude_analyzer.py, url_reputation.py
│   │   ├── integrations/        ← gmail_client.py, outlook_client.py, stripe_client.py,
│   │   │                          twilio_client.py, email_alert_client.py
│   │   ├── models/              ← DB models: User, FamilyLink, Alert, Subscription
│   │   ├── services/            ← alerting.py, email_ingestion.py, family_linking.py
│   │   └── api/                 ← route handlers, versioned
│   ├── tests/
│   └── requirements.txt
├── browser-extension/
│   ├── manifest.json            ← Manifest V3
│   └── src/                     ← background.ts, content.ts, popup/
├── dashboard/                   ← web frontend for the monitor
└── mobile-app/                  ← phase 2, placeholder only for now
```

---

## Privacy & Consent — Read Before Writing Ingestion/Detection Code

This product reads another adult's email. That requires:

- Explicit OAuth consent from the **protected person's own account** — never
  credential-sharing, never scraping without their sign-off in the flow.
- Minimum necessary data access: scan headers/links/sender metadata for
  scoring first; only send full body content to the Claude API narrative
  step when a heuristic has already flagged something as suspicious, and
  say so plainly in the privacy doc.
- A visible, plain-language disclosure to the protected person about what
  the monitor can and cannot see (e.g., monitor sees "flagged: fake bank
  email, did you click it?" — not the protected person's full inbox).
- Defined data retention limits for stored alert content.

Do not build ingestion or storage logic before `docs/PRIVACY_AND_CONSENT.md`
exists and reflects the actual data flow. Flag it if a feature request would
violate it rather than silently building around it.

---

## Coding Conventions (project-specific additions)

- Detection logic (`backend/app/detection/`) must be unit-testable without
  live network calls — mock Gmail/Graph/Claude/threat-intel responses in
  `backend/tests/`.
- Risk scoring: 1–10 scale, consistent with the Shadow IT Scanner
  convention. Every alert must carry a human-readable rationale, not just a
  number.
- All Claude API prompts live in one module as named constants (mirrors
  `ai/prompts.py` in Shadow IT Scanner) — never inline prompt strings in
  route handlers or services.
- OAuth tokens and any credential material: encrypted at rest, never logged,
  never included in error messages.
- New backend module → matching pytest file in the same session unless told
  otherwise.

## What NOT to Do

- Do not build SMS ingestion in v1 — it's explicitly out of scope until the
  roadmap says otherwise (see Scope Decisions above).
- Do not invent a billing/hosting decision silently — those are listed as
  "Not Yet Decided" for a reason; surface the question instead of picking
  for the user.
- Do not commit `.env`, OAuth client secrets, Stripe keys, or Twilio
  credentials — this is a **public** repo.
- Do not add mobile-app implementation code yet; it's a phase 2 placeholder
  until the email + browser extension path is working end to end.
