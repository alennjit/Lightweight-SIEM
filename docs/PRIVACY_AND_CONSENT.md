# Privacy & Consent

This document is the non-negotiable design constraint for every feature
that touches the protected person's email, links, or activity. Read this
before writing ingestion, detection, or storage code. If a feature request
conflicts with this document, flag the conflict — don't quietly build
around it.

## Why This Matters

The product's entire value proposition is that a family member can see
when their protected person is at risk. That is also, functionally, a
surveillance relationship between two adults. It only holds up — legally,
ethically, and for user trust — if consent and data minimization are real,
not cosmetic.

## Core Rules

1. **Consent comes from the protected person's own account.**
   The protected person authorizes the Gmail/Outlook OAuth connection and
   installs the browser extension themselves, or explicitly walks through
   a guided setup with the monitor present. Credential-sharing or setting
   this up *for* someone without their sign-off is out of scope, full stop.

2. **The monitor does not get a mirror of the inbox.**
   The monitor sees: that an alert fired, a plain-language summary of the
   risk ("this looks like a fake bank email asking to verify your account"),
   and whether the protected person appears to have interacted with it
   (opened/clicked). The monitor does not get raw email body content,
   unrelated emails, or general inbox browsing.

3. **Minimum necessary access, staged.**
   - Stage 1 (always): headers, sender domain, links, subject line — enough
     for heuristic scoring.
   - Stage 2 (only if Stage 1 flags something): full body content may be
     sent to the Claude API for a narrative explanation. This is the
     highest-sensitivity data flow in the system and must stay scoped to
     already-flagged messages, never bulk-processed.

4. **Disclosure is visible, not buried.**
   Both parties see, in plain language, what the monitor can and cannot
   see, at setup time and reachable at any time afterward — not just in a
   ToS document nobody reads.

5. **Data retention is bounded.**
   Alert content (flagged message metadata/narrative) has a defined
   retention window. Full email body content sent to Claude for narrative
   generation is not retained beyond generating the alert — retention
   policy and exact windows to be finalized before any real user data
   flows through the system.

6. **Revocation is immediate and easy.**
   Either party can end the monitoring relationship. The protected person
   can revoke OAuth access at any time (both from within the product and
   from their Google/Microsoft account settings — surface that path).

## Explicitly Out of Scope

- Reading messages/emails unrelated to phishing/scam detection.
- Location tracking, browsing history beyond flagged-link events, or any
  data collection not directly in service of the phishing-alert function.
- Any setup path that doesn't involve the protected person's active,
  informed consent.

## Open Questions (resolve before handling real user data)

- Exact data retention windows for alert content and any transient body
  text sent to Claude.
- Data deletion flow when a subscription ends or a monitoring relationship
  is revoked.
- Applicable regulatory considerations (state-level privacy law, any
  elder-care-adjacent regulation) — needs a real legal review before
  launch, not just an engineering judgment call.
