# Roadmap

## Phase 1 — Email + Browser (current focus)

1. Backend skeleton: FastAPI app, config/env loading, health check, DB
   models, auth scaffolding.
2. Gmail OAuth integration → fetch headers/links for new mail.
3. Heuristic detection engine (`heuristics.py`) with unit tests against
   known-phishing and known-clean sample sets.
4. Family linking + consent flow (protected person ↔ monitor).
5. Alerting: pick one channel first (likely email, lowest integration
   cost) to prove the loop end-to-end, then add push and SMS (Twilio).
6. Browser extension: link-reputation check + warning interstitial.
7. Minimal monitor dashboard: alert history + link status.
8. Outlook/Microsoft Graph OAuth (second email provider).
9. Claude-generated risk narratives wired into alerts.
10. Subscription billing (Stripe) gating access.

## Phase 2 — Android App

- Native Android app: notification listener + SMS Retriever API for
  on-device SMS/smishing detection.
- Extends the same backend detection pipeline — new ingestion source, not
  a new detection engine.

## Phase 3 — iOS Parity (email/browser only, revisit SMS)

- iOS app covering email + browser protection to match Android's non-SMS
  feature set.
- Revisit SMS coverage on iOS only if Apple's platform APIs change, or via
  an opt-in forwarding workaround — evaluate UX cost against non-technical
  target users before committing.

## Deferred / Not Scheduled

- SMS/smishing detection (blocked on Phase 2/3 sequencing above).
- Enterprise/multi-family or MSP-resale features — this product is scoped
  to single-household use for now.

## How to Use This File

Update it when scope actually changes, not speculatively. If a phase 1 item
gets deferred, move it here with a one-line reason instead of deleting it.
