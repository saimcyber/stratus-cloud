# Deploying Stratus (free tiers)

The deployment uses three hosts, and each one gets only the secrets it needs:

| Piece | Host | Secrets it gets |
|---|---|---|
| Stratus KMS | Render web service `stratus-kms` | `KMS_DATABASE_URL`, `ROOT_KEK`, `JWT_PRIVATE_KEY` |
| Stratus Vault | Render web service `stratus-vault` | `VAULT_DATABASE_URL`, `JWT_PUBLIC_KEY` |
| Console | Vercel project (root `web/`) | none (only the two public service URLs) |
| Databases | Neon Postgres | two databases, two roles |

## 1. Push to GitHub

```bash
git remote add origin https://github.com/<you>/stratus-cloud.git
git push -u origin main
```

## 2. Neon: two databases, two roles, and the secrets

1. Create a project in the Neon console (free plan, region close to Render, e.g. AWS Singapore).
2. Copy the owner connection string (`neondb_owner`, database `neondb`) from **Connect** into a file **outside** the repo, e.g. `../stratus-prod/admin-url.txt`.
3. Run:

   ```bash
   python scripts/setup_postgres.py --admin-url-file ../stratus-prod/admin-url.txt --out ../stratus-prod
   ```

   It creates `kms_app` and `vault_app` as plain login roles, the `kms` and `vault` databases owned by them, revokes `CONNECT` from `PUBLIC`, and checks that neither role can open the other database. It then writes `kms.env` and `vault.env` with the database URLs, a fresh `ROOT_KEK`, and the token signing key pair. Nothing secret is printed.

Roles created through Neon's dashboard belong to `neon_superuser`, which can read every database, so the script creates its own roles with SQL instead.

Keep `kms.env` safe. **If `ROOT_KEK` is lost or changed, every stored object becomes permanently undecryptable**, which is crypto-shredding by accident.

## 4. Render

1. **New → Blueprint**, then pick the repo. Render reads `render.yaml` and creates `stratus-kms` and `stratus-vault`.
2. Fill in the `sync: false` variables from `kms.env` and `vault.env` (only the part after `=`).
   * For the KMS: `KMS_DATABASE_URL`, `ROOT_KEK` and `JWT_PRIVATE_KEY`.
   * For the Vault: `VAULT_DATABASE_URL` and `JWT_PUBLIC_KEY`.
   * For both, set `ALLOWED_ORIGINS` to your Vercel URL (ours is `https://stratus-cloud-one.vercel.app`). You can fill it in after step 5 and redeploy.
3. Wait until both services show `/health` as healthy. The KMS seeds demo tenants, users and keys on first boot, and the Vault seeds the three demo buckets.

## 5. Vercel

1. **Add New → Project**, import the repo and set **Root Directory** to `web`. The framework preset is Vite.
2. Add the environment variables:
   * `VITE_KMS_URL` = `https://stratus-kms.onrender.com`
   * `VITE_VAULT_URL` = `https://stratus-vault.onrender.com`
3. Deploy. `web/vercel.json` handles SPA routing and security headers.

## 6. Seed sample files and check

```bash
python scripts/warmup.py --kms https://stratus-kms.onrender.com --vault https://stratus-vault.onrender.com
python scripts/seed_objects.py --kms https://stratus-kms.onrender.com --vault https://stratus-vault.onrender.com
python scripts/loadtest.py --kms https://stratus-kms.onrender.com --vault https://stratus-vault.onrender.com -n 60
```

## Resetting the live demo data

```bash
python scripts/reset_demo.py --env-file ../stratus-prod/kms.env --env-file ../stratus-prod/vault.env --kms https://stratus-kms.onrender.com --vault https://stratus-vault.onrender.com
```

The script refuses to touch a server database unless the matching `ROOT_KEK` is supplied, so the seed keys are always sealed with the live root key.

## Before the live demo

Render's free services sleep after about 15 minutes of inactivity, and the first request can take up to a minute. Run `warmup.py` about two minutes before presenting. The sign-in page also retries while the KMS wakes up.
