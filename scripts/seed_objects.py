"""Upload a few sample files (encrypted client-side) so the demo buckets aren't empty.

    python scripts/seed_objects.py --kms http://localhost:8001 --vault http://localhost:8002
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk"))
from stratus_sdk import StratusClient  # noqa: E402

SAMPLES = {
    ("alice", "acme-patient-records", "alias/patient-records"): {
        "intake/patient-4471.txt": b"Patient 4471\nDiagnosis: type 2 diabetes\nPrescribed: metformin 500mg\n",
        "intake/patient-4472.txt": b"Patient 4472\nAllergies: penicillin\nBlood type: O-\n",
        "radiology/report-0193.txt": b"Chest X-ray: no acute findings. Follow up in 6 months.\n",
    },
    ("alice", "acme-billing-exports", "alias/billing-rsa"): {
        "2026-10/invoices.csv": b"invoice,patient,amount\nINV-1001,4471,12500\nINV-1002,4472,8300\n",
    },
    ("mallory", "globex-ledgers", "alias/ledger"): {
        "q3/ledger.csv": b"account,balance\nops,1200000\nr&d,880000\n",
    },
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kms", default="http://localhost:8001")
    ap.add_argument("--vault", default="http://localhost:8002")
    args = ap.parse_args()
    for (user, bucket, alias), files in SAMPLES.items():
        c = StratusClient(httpx.Client(base_url=args.kms, timeout=60), httpx.Client(base_url=args.vault, timeout=60))
        c.demo_login(user)
        kid = c.key_id(alias)
        for name, data in files.items():
            meta = c.put_object(bucket, name, data, kid)
            print(f"{user:8} {bucket}/{name}  ({meta['stored_size']} ciphertext bytes, {alias} v{meta['envelope']['kms_key_version']})")


if __name__ == "__main__":
    main()
