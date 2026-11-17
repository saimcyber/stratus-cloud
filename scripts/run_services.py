"""Run Stratus KMS (:8001) and Stratus Vault (:8002) locally as two separate processes.

    python scripts/run_services.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVICES = [("kms", "stratus_kms.main:app", 8001), ("vault", "stratus_vault.main:app", 8002)]


def main() -> None:
    procs = [
        subprocess.Popen([sys.executable, "-m", "uvicorn", app, "--port", str(port), "--timeout-keep-alive", "30"],
                         cwd=ROOT / "services" / name)
        for name, app, port in SERVICES
    ]
    print("Stratus KMS   -> http://localhost:8001/docs\nStratus Vault -> http://localhost:8002/docs")
    try:
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
