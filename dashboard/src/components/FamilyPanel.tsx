import { useEffect, useState, type FormEvent } from "react";
import { createInvite, fetchLinks, redeemInvite, revokeLink } from "../api";
import type { FamilyLink, Invite, Me } from "../types";

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : "Something went wrong.";
}

/** Monitor enters the code a protected person shared with them. */
export function RedeemInviteForm({ onLinked }: { onLinked: () => void }) {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await redeemInvite(code);
      setCode("");
      onLinked();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form className="invite-form" onSubmit={handleSubmit}>
      <label className="field">
        Invite code
        <input
          value={code}
          onChange={(e) => setCode(e.target.value.toUpperCase())}
          placeholder="ABCD-EFGH"
          autoComplete="off"
          spellCheck={false}
          maxLength={20}
          required
        />
      </label>
      <button type="submit" className="button-primary" disabled={submitting}>
        {submitting ? "Checking…" : "Link"}
      </button>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
    </form>
  );
}

function InviteCreator() {
  const [invite, setInvite] = useState<Invite | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleCreate() {
    setError(null);
    try {
      setInvite(await createInvite());
    } catch (err) {
      setError(errorText(err));
    }
  }

  return (
    <div className="invite-creator">
      {invite ? (
        <div className="invite-code" role="status">
          <span className="invite-code__label">Share this code with your family member</span>
          <code className="invite-code__value">{invite.code}</code>
          <span className="invite-code__hint">
            Works once, until{" "}
            {new Date(invite.expires_at).toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric" })}
            . Only share it with someone you trust.
          </span>
        </div>
      ) : (
        <button type="button" className="button-primary" onClick={handleCreate}>
          Create an invite code
        </button>
      )}
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

export function FamilyPanel({ me, onLinksChanged }: { me: Me; onLinksChanged: () => void }) {
  const [links, setLinks] = useState<FamilyLink[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const isProtected = me.role === "protected";

  useEffect(() => {
    let cancelled = false;
    fetchLinks()
      .then((data) => !cancelled && setLinks(data))
      .catch((err: unknown) => !cancelled && setError(errorText(err)));
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  function changed() {
    setRefreshKey((key) => key + 1);
    onLinksChanged();
  }

  async function handleRemove(link: FamilyLink) {
    const prompt = isProtected
      ? `Stop sharing alerts with ${link.display_name}? They'll lose access right away.`
      : `Stop watching out for ${link.display_name}? You'll stop seeing their alerts.`;
    if (!window.confirm(prompt)) return;
    try {
      await revokeLink(link.id);
      changed();
    } catch (err) {
      setError(errorText(err));
    }
  }

  return (
    <div className="family">
      <section className="history__panel" aria-labelledby="family-heading">
        <h3 id="family-heading">{isProtected ? "Who gets your alerts" : "People you watch out for"}</h3>
        <p className="history__panel-hint">
          {isProtected
            ? "Family members you add can see alerts about risky messages — never your other email. You can remove anyone at any time."
            : "You'll see alerts for the people below. They can remove you at any time."}
        </p>
        {error && <p className="form-error">{error}</p>}
        {links === null ? (
          <p className="loading-state">Loading…</p>
        ) : links.length === 0 ? (
          <p className="empty-state__hint">{isProtected ? "Nobody yet." : "Nobody yet — enter a code below."}</p>
        ) : (
          <ul className="link-list">
            {links.map((link) => (
              <li key={link.id} className="link-row">
                <span className="link-row__name">{link.display_name}</span>
                <span className="link-row__since">
                  since {new Date(link.created_at).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}
                </span>
                <button type="button" className="button-quiet" onClick={() => handleRemove(link)}>
                  Remove
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="history__panel" aria-labelledby="add-heading">
        <h3 id="add-heading">{isProtected ? "Add a family member" : "Add someone"}</h3>
        <p className="history__panel-hint">
          {isProtected
            ? "Create a one-time code and give it to them in person or by phone. They enter it in their own account."
            : "Ask them to create an invite code in their account and read it to you."}
        </p>
        {isProtected ? <InviteCreator /> : <RedeemInviteForm onLinked={changed} />}
      </section>
    </div>
  );
}
