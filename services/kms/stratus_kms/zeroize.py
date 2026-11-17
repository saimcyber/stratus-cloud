"""Best-effort secure memory zeroization for key material.

Python `bytes` objects are immutable and may be copied by the interpreter or by
OpenSSL bindings, so true zeroization is impossible in CPython. What we *can*
do is keep every secret we own in a mutable `bytearray` and overwrite it with
zeros (via memset, which the optimiser cannot elide) as soon as it is no longer
needed. The residual risk is documented in docs/threat-model.md.
"""
from __future__ import annotations

import ctypes
from contextlib import contextmanager
from typing import Iterator


def zeroize(buf: bytearray) -> None:
    """Overwrite a bytearray in place with zeros."""
    if not isinstance(buf, bytearray):
        raise TypeError("zeroize() only works on mutable bytearray buffers")
    size = len(buf)
    if size:
        ctypes.memset((ctypes.c_char * size).from_buffer(buf), 0, size)


@contextmanager
def secret(buf: bytes | bytearray) -> Iterator[bytearray]:
    """Hold key material in a bytearray and wipe it when the block exits."""
    owned = buf if isinstance(buf, bytearray) else bytearray(buf)
    try:
        yield owned
    finally:
        zeroize(owned)
