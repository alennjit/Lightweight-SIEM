import { useState, type FormEvent } from "react";
import { login, register } from "../api";
import type { Me, Role } from "../types";

type Mode = "signin" | "signup";

const ROLE_CHOICES: { role: Role; title: string; detail: string }[] = [
  {
    role: "protected",
    title: "Protect my inbox",
    detail: "We check your email for scams, and family members you invite get a heads-up.",
  },
  {
    role: "monitor",
    title: "Watch out for someone",
    detail: "Get alerts for a parent or relative. They'll give you an invite code.",
  },
];

export function AuthScreen({ onSignedIn }: { onSignedIn: (me: Me) => void }) {
  const [mode, setMode] = useState<Mode>("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState<Role>("protected");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const me = mode === "signin" ? await login(email, password) : await register(email, password, displayName, role);
      setPassword("");
      onSignedIn(me);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setSubmitting(false);
    }
  }

  function switchMode(next: Mode) {
    setMode(next);
    setError(null);
  }

  return (
    <div className="auth">
      <div className="auth__card">
        <h2 className="auth__title">{mode === "signin" ? "Sign in" : "Create an account"}</h2>
        <form className="auth__form" onSubmit={handleSubmit}>
          {mode === "signup" && (
            <>
              <fieldset className="role-choice">
                <legend>Who is this account for?</legend>
                {ROLE_CHOICES.map((choice) => (
                  <label key={choice.role} className={role === choice.role ? "role-option is-selected" : "role-option"}>
                    <input
                      type="radio"
                      name="role"
                      value={choice.role}
                      checked={role === choice.role}
                      onChange={() => setRole(choice.role)}
                    />
                    <span className="role-option__title">{choice.title}</span>
                    <span className="role-option__detail">{choice.detail}</span>
                  </label>
                ))}
              </fieldset>
              <label className="field">
                Your name
                <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="name" required />
              </label>
            </>
          )}
          <label className="field">
            Email
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              required
            />
          </label>
          <label className="field">
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete={mode === "signin" ? "current-password" : "new-password"}
              minLength={mode === "signup" ? 12 : undefined}
              required
            />
            {mode === "signup" && <span className="field__hint">At least 12 characters. A short phrase works well.</span>}
          </label>
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <button type="submit" className="button-primary" disabled={submitting}>
            {submitting ? "Please wait…" : mode === "signin" ? "Sign in" : "Create account"}
          </button>
        </form>
        <p className="auth__switch">
          {mode === "signin" ? (
            <>
              New here?{" "}
              <button type="button" className="link-button" onClick={() => switchMode("signup")}>
                Create an account
              </button>
            </>
          ) : (
            <>
              Already have an account?{" "}
              <button type="button" className="link-button" onClick={() => switchMode("signin")}>
                Sign in
              </button>
            </>
          )}
        </p>
      </div>
    </div>
  );
}
