"""Verify the CNF MD5 encoder agrees with hashlib on 20 random messages.

For each test we build the CNF with ALL message bits as fresh variables
(no constants in the message block), fix them to the chosen message via unit
clauses, run Cadical, decode the four output words, and compare to
hashlib.md5(message).digest().
"""
from __future__ import annotations
import hashlib
import random
import sys

from pysat.solvers import Cadical195

from circuit import CNF
from md5_cnf import md5_cnf_from_bytes, hash_words_to_bytes


def check(message: bytes) -> tuple[bool, str, str, int, int]:
    cnf = CNF()
    # All input bits free, then forced via fix_bits (so the encoder doesn't
    # cheat by folding constants away).
    free = list(range(len(message) * 8))
    block_words, hash_words = md5_cnf_from_bytes(cnf, message, free_bit_positions=free)
    # Force the (now-free) message bits to the actual message.
    for byte_idx, byte_val in enumerate(message):
        w_index = byte_idx // 4
        for b in range(8):
            bit_in_word = (byte_idx % 4) * 8 + b
            lit = block_words[w_index][bit_in_word]
            v = (byte_val >> b) & 1
            cnf.fix_bit(lit, v)

    with Cadical195(bootstrap_with=cnf.clauses) as s:
        if not s.solve():
            return False, "UNSAT", hashlib.md5(message).hexdigest(), cnf.n_vars, len(cnf.clauses)
        model = set(s.get_model())
    got_words = [cnf.word_value(w, model) for w in hash_words]
    got = hash_words_to_bytes(got_words).hex()
    exp = hashlib.md5(message).hexdigest()
    return got == exp, got, exp, cnf.n_vars, len(cnf.clauses)


def main() -> int:
    random.seed(20260524)
    failures = 0
    # Mix of edge cases + 20 random
    tests = [b"", b"a", b"abc", b"hello"]
    for _ in range(20):
        n = random.randint(0, 55)
        tests.append(bytes(random.randint(0, 255) for _ in range(n)))
    for m in tests:
        ok, got, exp, nv, nc = check(m)
        flag = "OK " if ok else "FAIL"
        head = m[:24].hex() + ("…" if len(m) > 24 else "")
        print(f"[{flag}] len={len(m):2d} msg={head:<50} hash={got}  (vars={nv}, cl={nc})")
        if not ok:
            print(f"        expected hash={exp}")
            failures += 1
    if failures:
        print(f"\n!! {failures} failures")
        return 1
    print("\nall MD5 CNF checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
