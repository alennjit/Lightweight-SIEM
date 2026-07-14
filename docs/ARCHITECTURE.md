# Architecture

Target shape for v1 (email + browser). This is a design document, not a
description of what's implemented yet — see [README.md](../README.md) for
current build status.

## Components

### Backend (`backend/`)

FastAPI service, single deployable for v1 (split out later only if load
demands it — no premature microservices).

- **`app/integrations/`** — one client module per external system:
  `gmail_client.py`, `outlook_client.py` (OAuth + message fetch),
  `stripe_client.py` (billing), `twilio_client.py` (SMS alerts),
  `email_alert_client.py` (transactional email alerts). Each wraps its API
  with try/except and meaningful, non-leaky error messages — never log
  tokens or credentials.

- **`app/detection/`**
  - `heuristics.py` — rule-based scoring: sender/domain spoofing checks,
    urgency/credential-harvesting language patterns, known-bad domain
    lookups. Produces a 1–10 risk score with a rationale, always.
  - `url_reputation.py` — link reputation lookups against a threat intel
    source (VirusTotal / PhishTank / Google Safe Browsing — TBD, see
    CLAUDE.md "Not Yet Decided").
  - `claude_analyzer.py` — invoked only after a heuristic flag. Produces
    the plain-language risk narrative shown to the monitor. Prompts live
    in a dedicated constants module, never inlined.

- **`app/services/`**
  - `email_ingestion.py` — polls/receives webhook events for new mail,
    hands headers+links to `heuristics.py` first.
  - `alerting.py` — routes a confirmed flag to the monitor's chosen
    channel (push/SMS/email), records the alert.
  - `family_linking.py` — manages the consent-gated relationship between
    a protected-person account and one or more monitor accounts.

- **`app/models/`** — `User`, `FamilyLink`, `Alert`, `Subscription`.
  Multi-tenant from day one: every row scoped to an account, no
  cross-account queries without an explicit join through `FamilyLink`.

- **`app/api/`** — versioned route handlers (`/api/v1/...`). Auth required
  on every route except health check.

### Browser Extension (`browser-extension/`)

Manifest V3, Chrome/Edge first (Manifest V3 is also Safari-compatible with
some adjustment — revisit once Chrome/Edge path works).

- `background.ts` — service worker; calls backend's link-reputation
  endpoint on navigation events.
- `content.ts` — injects a warning interstitial when a URL comes back
  flagged, before the destination page can capture input.
- `popup/` — status UI for the protected person (minimal — this product's
  UX target is "gets out of the way until it matters").

### Dashboard (`dashboard/`)

Monitor-facing web app. Framework not yet finalized (leaning React +
TypeScript + Vite). Shows alert history, link status, account/consent
management, subscription status.

### Mobile App (`mobile-app/`)

Phase 2 placeholder. Not implemented in v1. When it starts: Android first,
using SMS Retriever API + notification listener for on-device coverage
that the browser/email path can't reach. iOS follow-up will be scoped to
email/browser parity only, given SMS API restrictions.

## Data Flow (v1)

```
Gmail/Outlook OAuth ──▶ email_ingestion.py ──▶ heuristics.py
                                                     │
                                        flagged? ────┴──── not flagged: no-op
                                            │
                                            ▼
                                   claude_analyzer.py (narrative)
                                            │
                                            ▼
                                      alerting.py ──▶ monitor (push/SMS/email)
                                            │
                                            ▼
                                    dashboard (history, status)
```

Browser extension path is independent and synchronous: navigation event →
`url_reputation.py` lookup → allow or interstitial warning, no email
pipeline involved.

## Open Architectural Questions

See CLAUDE.md → "Not Yet Decided" for the live list (frontend framework,
hosting target, billing provider, threat intel source). Don't resolve these
unilaterally in code — surface them.
