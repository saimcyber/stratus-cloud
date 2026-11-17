"""Wake both free-tier services before a demo (Render spins idle services down).

    python scripts/warmup.py --kms https://stratus-kms.onrender.com --vault https://stratus-vault.onrender.com
"""
from __future__ import annotations

import argparse
import time

import httpx


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kms", required=True)
    ap.add_argument("--vault", required=True)
    args = ap.parse_args()
    for name, url in (("KMS", args.kms), ("Vault", args.vault)):
        for attempt in range(12):
            t0 = time.perf_counter()
            try:
                r = httpx.get(f"{url.rstrip('/')}/health", timeout=90)
                if r.status_code == 200:
                    print(f"{name:6} up in {time.perf_counter() - t0:.1f}s  {r.json()}")
                    break
            except httpx.HTTPError as exc:
                print(f"{name:6} attempt {attempt + 1}: {exc.__class__.__name__}")
            time.sleep(5)
        else:
            print(f"{name:6} did not come up")


if __name__ == "__main__":
    main()
