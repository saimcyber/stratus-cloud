"""Put the demo back to its starting state: wipe both databases, re-create the seed tenants,
users, keys and buckets, then (if the services are running) upload the sample files again.

    python scripts/reset_demo.py                 # asks before wiping
    python scripts/reset_demo.py --yes           # no prompt
    python scripts/reset_demo.py --no-samples    # skip re-uploading sample files

    # the live deployment: use the production env files written by setup_postgres.py
    python scripts/reset_demo.py --env-file ../stratus-prod/kms.env --env-file ../stratus-prod/vault.env ^
        --kms https://<kms>.onrender.com --vault https://<vault>.onrender.com

Without --env-file, each service's database and keys come from its local .env, exactly as when it
runs locally. The keys are never changed, so sessions already signed in stay valid. The seed keys
are sealed with whichever ROOT_KEK is in effect, so a live reset must use the live ROOT_KEK.
"""
from __future__ import annotations

import argparse
import os
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


def read_env_file(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip()
    return values


def run_in(service: str, code: str, env: dict[str, str]) -> None:
    subprocess.run([sys.executable, "-c", code], cwd=ROOT / "services" / service, env=env, check=True)


def up(url: str) -> bool:
    try:
        return httpx.get(f"{url}/health", timeout=90).status_code == 200  # free hosts wake slowly
    except httpx.HTTPError:
        return False


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    ap.add_argument("--no-samples", action="store_true", help="don't re-upload the sample files")
    ap.add_argument("--kms", default="http://127.0.0.1:8001")
    ap.add_argument("--vault", default="http://127.0.0.1:8002")
    ap.add_argument("--env-file", action="append", type=Path, default=[],
                    help="extra env file(s), e.g. the production kms.env and vault.env")
    args = ap.parse_args()

    env = dict(os.environ)
    for f in args.env_file:
        env.update(read_env_file(f))
    kms_db = env.get("KMS_DATABASE_URL", "")
    if kms_db and not kms_db.startswith("sqlite") and not env.get("ROOT_KEK"):
        sys.exit("KMS_DATABASE_URL points at a server database but ROOT_KEK was not supplied with it. "
                 "Pass the matching kms.env with --env-file, or the seed keys would be sealed with the local root key.")

    if not args.yes:
        answer = input("This deletes every key, file and log entry in both databases. Type 'reset' to continue: ")
        if answer.strip() != "reset":
            print("Cancelled.")
            return

    run_in("kms", KMS_RESET, env)
    run_in("vault", VAULT_RESET, env)

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
