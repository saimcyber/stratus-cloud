"""Put the demo back to its starting state: wipe both databases, re-create the seed tenants,
users, keys and buckets, then (if the services are running) upload the sample files again.

    python scripts/reset_demo.py                 # asks before wiping
    python scripts/reset_demo.py --yes           # no prompt
    python scripts/reset_demo.py --no-samples    # skip re-uploading sample files

Works on SQLite (local) and Postgres: each service's database comes from its own .env or
environment (KMS_DATABASE_URL / VAULT_DATABASE_URL), exactly as when the service runs.
The Root KEK and signing keys are not touched, so sessions already signed in stay valid.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent

KMS_RESET = """
from stratus_kms.db import Base, engine, init_db, SessionLocal
from stratus_kms.seed import seed
Base.metadata.drop_all(engine)
init_db()
with SessionLocal() as s:
    seed(s)
print("KMS    reset:", engine.url.render_as_string(hide_password=True))
"""

VAULT_RESET = """
from stratus_vault.db import Base, Bucket, engine, init_db, SessionLocal
from stratus_vault.main import SEED_BUCKETS
Base.metadata.drop_all(engine)
init_db()
with SessionLocal() as s:
    for name, tenant in SEED_BUCKETS:
        s.add(Bucket(name=name, tenant_id=tenant, created_by="stratus"))
    s.commit()
print("Vault  reset:", engine.url.render_as_string(hide_password=True))
"""


def run_in(service: str, code: str) -> None:
    subprocess.run([sys.executable, "-c", code], cwd=ROOT / "services" / service, check=True)


def up(url: str) -> bool:
    try:
        return httpx.get(f"{url}/health", timeout=5).status_code == 200
    except httpx.HTTPError:
        return False


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    ap.add_argument("--no-samples", action="store_true", help="don't re-upload the sample files")
    ap.add_argument("--kms", default="http://127.0.0.1:8001")
    ap.add_argument("--vault", default="http://127.0.0.1:8002")
    args = ap.parse_args()

    if not args.yes:
        answer = input("This deletes every key, file and log entry in both databases. Type 'reset' to continue: ")
        if answer.strip() != "reset":
            print("Cancelled.")
            return

    run_in("kms", KMS_RESET)
    run_in("vault", VAULT_RESET)

    if args.no_samples:
        return
    if up(args.kms) and up(args.vault):
        subprocess.run([sys.executable, str(ROOT / "scripts" / "seed_objects.py"),
                        "--kms", args.kms, "--vault", args.vault], check=True)
    else:
        print("Services not running, so sample files were skipped. Start them, then run scripts/seed_objects.py")
    print("Done. Sign out and back in on the console to refresh the page.")


if __name__ == "__main__":
    main()
