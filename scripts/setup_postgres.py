"""One-time production setup: two isolated Postgres databases + fresh service secrets.

    python scripts/setup_postgres.py --admin-url-file ../stratus-prod/admin-url.txt --out ../stratus-prod

admin-url.txt holds the owner connection string of an empty Postgres server (for Neon: the
neondb_owner string from the Connect dialog). The script then:

  * creates two login roles, kms_app and vault_app, with random passwords. They are plain roles,
    not members of any admin role, so neither can read the other's data;
  * creates the databases kms (owned by kms_app) and vault (owned by vault_app) and revokes
    CONNECT from PUBLIC, so each role can open only its own database;
  * checks that isolation actually holds by trying the cross connections;
  * writes kms.env and vault.env into --out with everything each service needs
    (database URL, ROOT_KEK and the token signing key for the KMS; only the public
    verification key for the Vault).

Secrets are written to files and never printed. Keep --out outside the git repository and back
up kms.env: losing ROOT_KEK makes every stored object permanently unreadable.
"""
from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

import psycopg
from psycopg import sql

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_secrets import generate  # noqa: E402

PAIRS = [("kms_app", "kms"), ("vault_app", "vault")]


def with_credentials(admin_url: str, user: str, password: str, database: str) -> str:
    parts = urlsplit(admin_url.replace("postgres://", "postgresql://", 1))
    host = parts.hostname or ""
    host = host.replace("-pooler.", ".")  # direct endpoint: no PgBouncer between psycopg and Postgres
    netloc = f"{quote(user)}:{quote(password, safe='')}@{host}" + (f":{parts.port}" if parts.port else "")
    return urlunsplit((parts.scheme, netloc, "/" + database, parts.query, ""))


def can_connect(url: str) -> bool:
    try:
        with psycopg.connect(url, connect_timeout=15) as c:
            c.execute("select 1")
        return True
    except psycopg.OperationalError:
        return False


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--admin-url-file", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    out = args.out
    if (out / "kms.env").exists() or (out / "vault.env").exists():
        sys.exit(f"{out} already has kms.env or vault.env; refusing to overwrite production secrets.")
    admin_url = args.admin_url_file.read_text(encoding="utf-8").strip().strip("'\"")
    if admin_url.startswith("psql "):
        admin_url = admin_url[5:].strip().strip("'\"")

    passwords = {role: secrets.token_urlsafe(24) for role, _ in PAIRS}
    with psycopg.connect(admin_url, autocommit=True, connect_timeout=20) as conn:
        me = conn.execute("select current_user").fetchone()[0]
        print(f"connected as {me} to {urlsplit(admin_url).hostname}")
        for role, db in PAIRS:
            exists = conn.execute("select 1 from pg_roles where rolname = %s", (role,)).fetchone()
            verb = "ALTER" if exists else "CREATE"
            conn.execute(sql.SQL(verb + " ROLE {} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {}")
                         .format(sql.Identifier(role), sql.Literal(passwords[role])))
            # Postgres 16: the creator needs membership to hand a database to this role.
            conn.execute(sql.SQL("GRANT {} TO {}").format(sql.Identifier(role), sql.Identifier(me)))
            if not conn.execute("select 1 from pg_database where datname = %s", (db,)).fetchone():
                conn.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(db), sql.Identifier(role)))
            conn.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(db)))
            conn.execute(sql.SQL("GRANT CONNECT, TEMPORARY ON DATABASE {} TO {}").format(sql.Identifier(db), sql.Identifier(role)))
            member_of = [r[0] for r in conn.execute(
                "select b.rolname from pg_auth_members m join pg_roles b on b.oid = m.roleid "
                "join pg_roles r on r.oid = m.member where r.rolname = %s", (role,))]
            print(f"{verb.lower()}d role {role}; database {db} owned by it; member of: {member_of or 'nothing'}")

    urls = {role: with_credentials(admin_url, role, passwords[role], db) for role, db in PAIRS}
    checks = {
        "kms_app   -> kms":   (can_connect(urls["kms_app"]), True),
        "vault_app -> vault": (can_connect(urls["vault_app"]), True),
        "vault_app -> kms":   (can_connect(with_credentials(admin_url, "vault_app", passwords["vault_app"], "kms")), False),
        "kms_app   -> vault": (can_connect(with_credentials(admin_url, "kms_app", passwords["kms_app"], "vault")), False),
    }
    ok = True
    for name, (got, want) in checks.items():
        ok &= got == want
        print(f"  {name}: {'connects' if got else 'refused'}  [{'ok' if got == want else 'UNEXPECTED'}]")
    if not ok:
        sys.exit("Isolation check failed; not writing env files.")

    keys = generate()
    out.mkdir(parents=True, exist_ok=True)
    (out / "kms.env").write_text(
        f"KMS_DATABASE_URL={urls['kms_app']}\n"
        f"ROOT_KEK={keys['ROOT_KEK']}\n"
        f"JWT_PRIVATE_KEY={keys['JWT_PRIVATE_KEY']}\n"
        "DEMO_MODE=true\n", encoding="utf-8")
    (out / "vault.env").write_text(
        f"VAULT_DATABASE_URL={urls['vault_app']}\n"
        f"JWT_PUBLIC_KEY={keys['JWT_PUBLIC_KEY']}\n"
        "DEMO_MODE=true\n", encoding="utf-8")
    print(f"wrote {out / 'kms.env'} and {out / 'vault.env'} (values not shown)")


if __name__ == "__main__":
    main()
