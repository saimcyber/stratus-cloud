"""Concurrency + multi-tenancy proof.

Fires N concurrent GenerateDataKey → Decrypt round-trips from two Acme users while
(a) the key is rotated several times mid-flight and (b) Mallory from Globex hammers the
same key with stolen wrapped blobs. Asserts:
  * every legitimate round-trip returns the same DEK it was issued (no corruption under races)
  * every rotation produced a unique version number
  * zero cross-tenant requests succeed

    python scripts/loadtest.py --kms http://127.0.0.1:8001 --vault http://127.0.0.1:8002 -n 100
"""
from __future__ import annotations

import argparse
import random
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk"))
from stratus_sdk import StratusClient, StratusError  # noqa: E402

CTX = {"tenant": "acme-health", "bucket": "acme-patient-records", "object": "loadtest.bin"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kms", default="http://127.0.0.1:8001")
    ap.add_argument("--vault", default="http://127.0.0.1:8002")
    ap.add_argument("-n", type=int, default=100, help="legitimate round-trips")
    ap.add_argument("--workers", type=int, default=24)
    args = ap.parse_args()

    limits = httpx.Limits(max_connections=64, max_keepalive_connections=64)

    def new_client(user: str) -> StratusClient:
        c = StratusClient(httpx.Client(base_url=args.kms, timeout=60, limits=limits),
                          httpx.Client(base_url=args.vault, timeout=60, limits=limits))
        c.demo_login(user)
        return c

    alice, bob, mallory = new_client("alice"), new_client("bob"), new_client("mallory")
    key = httpx.post(f"{args.kms}/keys", headers=alice._h, timeout=60,
                     json={"alias": f"loadtest-{int(time.time())}", "description": "load test"}).json()
    kid = key["key_id"]
    httpx.put(f"{args.kms}/keys/{kid}/access", headers=alice._h, json={"username": "bob", "role": "user"}, timeout=60)
    stolen = alice.generate_data_key(kid, CTX)["ciphertext_blob"]

    latencies: list[float] = []
    versions_seen: set[int] = set()
    rotations: list[int] = []
    cross_tenant_success = 0
    cross_tenant_blocked = 0
    failures: list[str] = []

    transport_retries = 0

    def with_retry(fn, *a):
        # Retries only *network* resets (Windows loopback can drop idle keep-alive sockets);
        # API-level errors are never retried and count as failures.
        nonlocal transport_retries
        for attempt in range(3):
            try:
                return fn(*a)
            except httpx.TransportError:
                transport_retries += 1
                if attempt == 2:
                    raise

    def legit(i: int) -> None:
        c = random.choice([alice, bob])
        t0 = time.perf_counter()
        try:
            dk = with_retry(c.generate_data_key, kid, CTX)
            back = with_retry(c.decrypt_data_key, dk["ciphertext_blob"], CTX)
            latencies.append((time.perf_counter() - t0) * 1000)
            versions_seen.add(dk["key_version"])
            if back["plaintext"] != dk["plaintext"]:
                failures.append(f"#{i}: DEK mismatch")
        except StratusError as e:
            failures.append(f"#{i}: {e}")

    def attack(_: int) -> None:
        nonlocal cross_tenant_success, cross_tenant_blocked
        try:
            with_retry(mallory.decrypt_data_key, stolen, CTX)
            cross_tenant_success += 1
        except StratusError as e:
            if e.status in (403, 429):
                cross_tenant_blocked += 1
            else:
                failures.append(f"attack: unexpected {e}")

    def rotate(_: int) -> None:
        rotations.append(with_retry(alice.rotate, kid)["rotated_to_version"])

    print(f"Firing {args.n} round-trips + {args.n // 4} cross-tenant attacks + 3 rotations on {args.workers} workers...")
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        work = [(legit, i) for i in range(args.n)] + [(attack, i) for i in range(args.n // 4)]
        random.shuffle(work)
        for slot, i in zip((args.n // 4, args.n // 2, 3 * args.n // 4), range(3)):
            work.insert(slot, (rotate, i))  # rotations land in the middle of the traffic
        jobs = [pool.submit(fn, i) for fn, i in work]
        for j in jobs:
            j.result()
    elapsed = time.perf_counter() - start

    # tidy up: crypto-shred the temporary key
    httpx.post(f"{args.kms}/keys/{kid}/schedule-deletion", headers=alice._h, json={"pending_minutes": 0}, timeout=60)

    lat = sorted(latencies)
    print("\n-- Results ------------------------------------------")
    print(f" legitimate round-trips  {len(latencies)}/{args.n} ok   in {elapsed:.2f}s ({len(latencies) / elapsed:.1f}/s)")
    if lat:
        print(f" latency (gen+decrypt)   p50 {statistics.median(lat):.1f} ms   p95 {lat[int(len(lat) * 0.95) - 1]:.1f} ms")
    print(f" rotations               versions {sorted(rotations)}   key versions used {sorted(versions_seen)}")
    print(f" cross-tenant attempts   {cross_tenant_blocked} blocked, {cross_tenant_success} succeeded")
    print(f" network retries         {transport_retries}")
    for f in failures[:10]:
        print("  !", f)

    ok = (not failures and cross_tenant_success == 0 and len(latencies) == args.n
          and len(set(rotations)) == len(rotations) == 3)
    print("\nPASS" if ok else "\nFAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
