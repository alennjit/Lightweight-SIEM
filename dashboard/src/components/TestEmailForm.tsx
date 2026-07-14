import { useState, type FormEvent } from "react";
import { scoreEmail } from "../api";
import type { EmailScoreResponse } from "../types";

export function TestEmailForm({ onScored }: { onScored: () => void }) {
  const [senderDomain, setSenderDomain] = useState("");
  const [subject, setSubject] = useState("");
  const [links, setLinks] = useState("");
  const [body, setBody] = useState("");
  const [result, setResult] = useState<EmailScoreResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const response = await scoreEmail({
        sender_domain: senderDomain,
        subject,
        links: links
          .split(",")
          .map((link) => link.trim())
          .filter(Boolean),
        body,
      });
      setResult(response);
      onScored();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="test-email-form" onSubmit={handleSubmit}>
      <h2>Test the detection engine</h2>
      <p className="hint">
        Simulates an inbound email through the same heuristic scoring the real ingestion pipeline
        will use. Nothing here sends real mail.
      </p>
      <label>
        Sender domain
        <input
          value={senderDomain}
          onChange={(e) => setSenderDomain(e.target.value)}
          placeholder="gmail.com"
          required
        />
      </label>
      <label>
        Subject
        <input
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          placeholder="Chase account alert: unusual activity detected"
          required
        />
      </label>
      <label>
        Links (comma-separated)
        <input
          value={links}
          onChange={(e) => setLinks(e.target.value)}
          placeholder="https://chase-alerts.com/verify"
        />
      </label>
      <label>
        Body
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          rows={4}
          placeholder="Dear customer, please confirm your identity immediately..."
        />
      </label>
      <button type="submit" disabled={submitting}>
        {submitting ? "Scoring…" : "Score this email"}
      </button>
      {error && <p className="error">{error}</p>}
      {result && (
        <div className={`result result--${result.flagged ? "flagged" : "clean"}`}>
          <p>
            <strong>Score:</strong> {result.score}/10 {result.flagged ? "— FLAGGED" : "— clean"}
          </p>
          <p>{result.rationale}</p>
        </div>
      )}
    </form>
  );
}
