"""Verify CNF SHA-1 encoder agrees with hashlib on 20 random messages."""
from __future__ import annotations
import hashlib
import random
import sys

from pysat.solvers import Cadical195

from circuit import CNF
from sha1_cnf import sha1_cnf_from_bytes, hash_words_to_bytes


def check(message: bytes) -> tuple[bool, str, str, int, int]:
    cnf = CNF()
    free = list(range(len(message) * 8))
    block_words, hash_words = sha1_cnf_from_bytes(cnf, message, free_bit_positions=free)
    # Force the message bits to the chosen values.
    msg_bits = len(message) * 8
    for byte_idx in range(len(message)):
        w_index = byte_idx // 4
        # In SHA-1's big-endian layout, byte_in_word = byte_idx % 4 maps to
        # bit positions [(3 - byte_in_word)*8 .. +8) within the word.
        byte_in_word = byte_idx % 4
        base = (3 - byte_in_word) * 8
        byte_val = message[byte_idx]
        for b in range(8):
            lit = block_words[w_index][base + b]
            cnf.fix_bit(lit, (byte_val >> b) & 1)

    with Cadical195(bootstrap_with=cnf.clauses) as s:
        if not s.solve():
            return False, "UNSAT", hashlib.sha1(message).hexdigest(), cnf.n_vars, len(cnf.clauses)
        model = set(s.get_model())
    got_words = [cnf.word_value(w, model) for w in hash_words]
    got = hash_words_to_bytes(got_words).hex()
    exp = hashlib.sha1(message).hexdigest()
    return got == exp, got, exp, cnf.n_vars, len(cnf.clauses)


def main() -> int:
    random.seed(20260524)
    failures = 0
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
        print(f"\n!! {failures} failures"); return 1
    print("\nall SHA-1 CNF checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
