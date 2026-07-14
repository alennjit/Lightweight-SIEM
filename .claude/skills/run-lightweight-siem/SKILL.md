---
name: run-lightweight-siem
description: How to launch and browser-drive the Lightweight SIEM backend (FastAPI) and dashboard (Vite/React) on this Windows dev machine, for verifying changes actually work end to end.
---

# Running Lightweight SIEM

## Backend (FastAPI, port 8000)

```bash
cd backend
".venv/Scripts/python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

If `.venv` doesn't exist yet: `python -m venv .venv` then
`.venv/Scripts/python.exe -m pip install -r requirements.txt`.

Health check: `curl http://127.0.0.1:8000/health` → `{"status":"ok"}`.

## Dashboard (Vite/React, port 5173)

```bash
cd dashboard
npm run dev
```

If `node_modules` doesn't exist yet: `npm install` first. Node/npm live at
`C:\Program Files\nodejs` — add to PATH if `node`/`npm` aren't found
(`export PATH="$PATH:/c/Program Files/nodejs"` in bash).

**Gotcha:** on this machine, Vite's dev server responds on
`http://localhost:5173` but *not* `http://127.0.0.1:5173` (connection
refused) — always use `localhost`, not the IP literal, when curling or
navigating a browser to it.

## Driving it in a browser (no chromium-cli on this machine)

This is a native Windows box, not a Linux container — `chromium-cli` isn't
available. Use Playwright directly instead:

```bash
mkdir -p /tmp/lwsiem-e2e && cd /tmp/lwsiem-e2e   # or $TEMP/lwsiem-e2e on Windows
npm init -y
npm install -D playwright
npx playwright install chromium   # ~115MB, one-time per machine unless cached
```

Then a plain `.mjs` script using `import { chromium } from "playwright"`,
`chromium.launch()`, `page.goto("http://localhost:5173")`, fill/click via
Playwright locators (never raw DOM `.value =` — React controlled inputs
won't see it), `page.screenshot()`, and check `console` events for errors.
Run it from inside that scratch directory (ESM `import` resolution needs
`node_modules` to be a real sibling, not just on `NODE_PATH`).

Delete the scratch directory when done — it's not part of the repo.

## Stopping

Both dev servers were started as background tasks in past sessions and
stopped via `TaskStop` on their task IDs once verification was done. Kill
by port if needed: find the PID bound to 8000/5173 and stop it.

## What This Verifies

The one representative path that proves the stack works: submit a
phishing-shaped test email through the dashboard's "Test the detection
engine" form → see `FLAGGED` with a score and rationale → see it appear in
"Recent alerts" above. If that round-trip works with no console errors,
backend detection, DB persistence, the alerts API, and the dashboard's
fetch/render path are all confirmed live end-to-end.
