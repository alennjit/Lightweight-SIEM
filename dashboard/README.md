# Dashboard

Monitor-facing web app for Lightweight SIEM — alert history and a
test-email form wired to the live backend. React + TypeScript + Vite.

## Running

```bash
npm install
npm run dev        # http://localhost:5173, expects the backend on :8000
```

See `.claude/skills/run-lightweight-siem/SKILL.md` at the repo root for the
full launch + browser-verification recipe, including a Windows-specific
gotcha (`localhost` works, `127.0.0.1` doesn't, for the dev server).

## Structure

- `src/api.ts` — typed fetch wrapper for the backend API
- `src/types.ts` — TypeScript types mirroring the backend's Pydantic schemas
- `src/components/AlertList.tsx` — fetches and renders stored alerts
- `src/components/TestEmailForm.tsx` — submits a test email to
  `/api/v1/emails/score` and shows the result

## Security Notes

Alert content (subject, sender, links, rationale) originates from
phishing-flagged email — treat it as attacker-influenced, not trusted app
data. See `~/.claude/skills/frontend-design/SKILL.md` (global skill) for
the rules this follows: no `dangerouslySetInnerHTML` on any of it, links
rendered as inert text rather than live `<a href>` elements, etc.

Not yet implemented: auth (there's no login), so there's nothing here yet
that reads session/OAuth tokens client-side. That constraint from the
frontend-design skill will matter once auth lands.
