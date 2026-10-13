"""Create fictional test accounts with realistic data in the local dev database.

    cd backend
    .venv/Scripts/python.exe -m scripts.seed_test_accounts --reset

Accounts (all on the reserved .test domain, so they can never be real):
- margaret@example.test  protected  — a month of history, 15 caught threats
- robert@example.test    protected  — a quieter inbox, a few threats
- daniel@example.test    monitor    — linked to Margaret and Robert
- sam@example.test       monitor    — linked to nobody (try the invite flow)

Passwords are random on every run, printed once and written to
backend/test-accounts.local.txt (gitignored). Refuses to run against
anything but a local SQLite database.

Alerts and scores come from running the same fictional samples as the public
demo through the real detection engine.
"""

from __future__ import annotations

import argparse
import logging
import random
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import inspect

from app.core.config import get_settings
from app.core.db import Base, SessionLocal, engine
from app.detection.heuristics import score_email
from app.models import alert as _alert  # noqa: F401  (register tables)
from app.models import gmail_account as _gmail_account  # noqa: F401
from app.models import scan_event as _scan_event  # noqa: F401
from app.models import user as _user  # noqa: F401
from app.models.alert import Alert
from app.models.scan_event import ScanEvent
from app.models.user import ROLE_MONITOR, ROLE_PROTECTED, FamilyLink, User
from app.services.accounts import create_user
from scripts.generate_demo_data import DAY, SAMPLES, Sample

logger = logging.getLogger(__name__)

BACKEND_DIR = Path(__file__).resolve().parents[1]
CREDENTIALS_FILE = BACKEND_DIR / "test-accounts.local.txt"
HISTORY_DAYS = 30


@dataclass(frozen=True)
class TestAccount:
    email: str
    display_name: str
    role: str
    note: str


ACCOUNTS = (
    TestAccount("margaret@example.test", "Margaret", ROLE_PROTECTED, "protected - busy inbox, 15 threats"),
    TestAccount("robert@example.test", "Robert", ROLE_PROTECTED, "protected - quieter inbox"),
    TestAccount("daniel@example.test", "Daniel", ROLE_MONITOR, "monitor - linked to Margaret and Robert"),
    TestAccount("sam@example.test", "Sam", ROLE_MONITOR, "monitor - linked to nobody"),
)


def _refuse_unless_local_sqlite() -> Path:
    """Only ever touch a local SQLite file — never a shared or production database."""
    url = get_settings().database_url
    if not url.startswith("sqlite:///"):
        sys.exit(f"Refusing to seed: DATABASE_URL is not a local SQLite file ({url.split('://')[0]}://...).")
    return (BACKEND_DIR / url.removeprefix("sqlite:///")).resolve()


def _schema_is_current() -> bool:
    """create_all can't add columns, so an old dev.db needs --reset."""
    inspector = inspect(engine)
    if not inspector.has_table("alerts"):
        return True
    return "owner_id" in {column["name"] for column in inspector.get_columns("alerts")}


def _random_password() -> str:
    # 4 groups of 4 from an unambiguous alphabet: easy to type, ~80 bits.
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4))


def _add_history(db, owner: User, samples: tuple[Sample, ...], clean_per_day: tuple[int, int], seed: int) -> int:
    """Store scored samples as alerts + scan events, plus clean-mail scan events per day."""
    now = datetime.now(timezone.utc)
    rng = random.Random(seed)
    caught = 0
    for sample in samples:
        result = score_email(
            sender_domain=sample.sender_domain, subject=sample.subject, links=list(sample.links), body=sample.body
        )
        when = now - timedelta(minutes=sample.minutes_ago)
        db.add(
            ScanEvent(
                owner_id=owner.id,
                scanned_at=when,
                score=result.score,
                flagged=result.flagged,
                categories=result.categories,
                flagged_link_count=len(sample.links) if result.flagged else 0,
            )
        )
        if result.flagged:
            caught += 1
            db.add(
                Alert(
                    owner_id=owner.id,
                    sender_domain=sample.sender_domain,
                    subject=sample.subject,
                    links=list(sample.links),
                    score=result.score,
                    rationale=result.rationale,
                    created_at=when,
                )
            )
    for days_ago in range(HISTORY_DAYS):
        for _ in range(rng.randint(*clean_per_day)):
            when = now - timedelta(days=days_ago, minutes=rng.randint(0, DAY - 1))
            db.add(ScanEvent(owner_id=owner.id, scanned_at=when, score=1, flagged=False, categories=[]))
    db.commit()
    return caught


def main() -> None:
    """Create the test accounts, their data and links; print the credentials once."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--reset", action="store_true", help="delete the local SQLite database first")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    db_path = _refuse_unless_local_sqlite()
    if args.reset:
        engine.dispose()
        db_path.unlink(missing_ok=True)
        logger.info("Deleted %s", db_path.name)
    elif not _schema_is_current():
        sys.exit("dev.db predates accounts (no owner columns). Re-run with --reset to recreate it.")

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(User).filter(User.email.in_([a.email for a in ACCOUNTS])).count():
            sys.exit("Test accounts already exist. Re-run with --reset to start fresh.")

        passwords: dict[str, str] = {}
        users: dict[str, User] = {}
        for account in ACCOUNTS:
            passwords[account.email] = _random_password()
            users[account.display_name] = create_user(
                db, account.email, passwords[account.email], account.display_name, account.role
            )

        margaret_caught = _add_history(db, users["Margaret"], SAMPLES, (12, 30), seed=1)
        robert_samples = tuple(s for s in SAMPLES if "Norton" in s.subject or "package" in s.subject or "Amazon" in s.subject or "order" in s.subject)
        robert_caught = _add_history(db, users["Robert"], robert_samples, (4, 12), seed=2)

        for person in ("Margaret", "Robert"):
            db.add(FamilyLink(monitor_user_id=users["Daniel"].id, protected_user_id=users[person].id))
        db.commit()
    finally:
        db.close()

    lines = [
        "Lightweight SIEM - local test accounts (fictional; regenerate with",
        "`python -m scripts.seed_test_accounts --reset`). Do not commit this file.",
        "",
    ]
    for account in ACCOUNTS:
        lines.append(f"{account.email:<24} {passwords[account.email]:<22} {account.note}")
    CREDENTIALS_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")

    logger.info("Seeded Margaret (%d threats) and Robert (%d threats); Daniel linked to both.", margaret_caught, robert_caught)
    print("\n" + "\n".join(lines[3:]))
    print(f"\nSaved to {CREDENTIALS_FILE.name} (gitignored).")


if __name__ == "__main__":
    main()
