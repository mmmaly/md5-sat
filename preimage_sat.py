"""SAT-based MD5 preimage formulas.

Two variants:

  (A) free-input-bits, n   — fix all but n bits of a known message m, force
      the hash to md5(m), ask the solver to recover the n unknown bits.
      Always SAT (the original bits are a witness).

  (B) constrained-output-bits, k — leave the entire message free, constrain
      only the first k bits of the output to a target value t. As k grows,
      satisfaction becomes rarer (collisions on a k-bit slice of the hash).

Both variants take a fixed message length in bytes (default: a single
55-byte block). The solver is asked once; we record SAT/UNSAT, the witness,
plus Cadical's conflicts/decisions/propagations/restarts.
"""
from __future__ import annotations
import hashlib
import time
from dataclasses import dataclass

from pysat.solvers import Cadical195

from circuit import CNF
from md5_cnf import md5_cnf_from_bytes, reference_md5, hash_words_to_bytes


@dataclass
class PreimageResult:
    sat: bool
    witness: bytes | None
    n_vars: int
    n_clauses: int
    encode_s: float
    bootstrap_s: float
    solve_s: float
    conflicts: int
    decisions: int
    propagations: int
    restarts: int


# ---------------------------------------------------------------------------
# Variant A: n free input bits
# ---------------------------------------------------------------------------

def build_free_input_cnf(message: bytes, free_bit_positions: list[int],
                         target_hash_words: list[int]) -> tuple[CNF, list[list[int]], list[list[int]]]:
    """Build CNF: md5(?) == target_hash, with `free_bit_positions` of `message`
    being free variables and the rest of the message fixed.
    """
    cnf = CNF()
    block_words, hash_words = md5_cnf_from_bytes(cnf, message,
                                                 free_bit_positions=free_bit_positions)
    # Force output to target.
    for word_idx, target_word in enumerate(target_hash_words):
        for bit_idx in range(32):
            lit = hash_words[word_idx][bit_idx]
            v = (target_word >> bit_idx) & 1
            cnf.fix_bit(lit, v)
    return cnf, block_words, hash_words


def solve_free_input(message: bytes, free_bit_positions: list[int],
                     target_hash_words: list[int] | None = None) -> PreimageResult:
    """If target_hash_words is None, computes md5(message) and uses that."""
    if target_hash_words is None:
        # Compute target from full message
        target_bytes = reference_md5(message)
        target_hash_words = [int.from_bytes(target_bytes[i:i+4], "little") for i in range(0, 16, 4)]
    t0 = time.perf_counter()
    cnf, block_words, _ = build_free_input_cnf(message, free_bit_positions, target_hash_words)
    t1 = time.perf_counter()
    solver = Cadical195(bootstrap_with=cnf.clauses)
    t2 = time.perf_counter()
    sat = solver.solve()
    t3 = time.perf_counter()
    stats = solver.accum_stats()
    witness: bytes | None = None
    if sat:
        model = set(solver.get_model())
        # Decode message: rebuild bytes from block_words bits, taking only
        # the original message-length bytes.
        out = bytearray(len(message))
        for byte_idx in range(len(message)):
            w_index = byte_idx // 4
            byte_val = 0
            for b in range(8):
                bit_in_word = (byte_idx % 4) * 8 + b
                lit = block_words[w_index][bit_in_word]
                if lit == cnf.TRUE:
                    bit = 1
                elif lit == cnf.FALSE:
                    bit = 0
                elif lit > 0:
                    bit = 1 if lit in model else 0
                else:
                    bit = 0 if -lit in model else 1
                byte_val |= (bit << b)
            out[byte_idx] = byte_val
        witness = bytes(out)
    solver.delete()
    return PreimageResult(
        sat=bool(sat), witness=witness,
        n_vars=cnf.n_vars, n_clauses=len(cnf.clauses),
        encode_s=t1 - t0, bootstrap_s=t2 - t1, solve_s=t3 - t2,
        conflicts=stats.get("conflicts", 0),
        decisions=stats.get("decisions", 0),
        propagations=stats.get("propagations", 0),
        restarts=stats.get("restarts", 0),
    )


# ---------------------------------------------------------------------------
# Variant B: k output bits constrained, all message bits free
# ---------------------------------------------------------------------------

def build_output_constrained_cnf(message_len: int, k_output_bits: int,
                                 target_hash_words: list[int]
                                 ) -> tuple[CNF, list[list[int]], list[list[int]]]:
    """All `message_len` message bytes are free; only the first `k_output_bits`
    of the resulting MD5 hash are constrained (to match the first k bits of
    target_hash_words, taken as a 128-bit little-endian sequence: bit 0 = LSB
    of word 0, bit 32 = LSB of word 1, etc.)."""
    cnf = CNF()
    # Use a dummy "message" of all zeros, but mark every bit as free.
    zero_msg = bytes(message_len)
    free = list(range(message_len * 8))
    block_words, hash_words = md5_cnf_from_bytes(cnf, zero_msg, free_bit_positions=free)
    # Constrain the first k_output_bits of the hash.
    for bit_idx in range(k_output_bits):
        word_idx = bit_idx // 32
        bit_in_word = bit_idx % 32
        target_word = target_hash_words[word_idx]
        v = (target_word >> bit_in_word) & 1
        lit = hash_words[word_idx][bit_in_word]
        cnf.fix_bit(lit, v)
    return cnf, block_words, hash_words


def solve_output_constrained(message_len: int, k_output_bits: int,
                              target_hash_words: list[int]) -> PreimageResult:
    t0 = time.perf_counter()
    cnf, block_words, _ = build_output_constrained_cnf(message_len, k_output_bits, target_hash_words)
    t1 = time.perf_counter()
    solver = Cadical195(bootstrap_with=cnf.clauses)
    t2 = time.perf_counter()
    sat = solver.solve()
    t3 = time.perf_counter()
    stats = solver.accum_stats()
    witness: bytes | None = None
    if sat:
        model = set(solver.get_model())
        out = bytearray(message_len)
        for byte_idx in range(message_len):
            w_index = byte_idx // 4
            byte_val = 0
            for b in range(8):
                bit_in_word = (byte_idx % 4) * 8 + b
                lit = block_words[w_index][bit_in_word]
                if lit == cnf.TRUE:
                    bit = 1
                elif lit == cnf.FALSE:
                    bit = 0
                elif lit > 0:
                    bit = 1 if lit in model else 0
                else:
                    bit = 0 if -lit in model else 1
                byte_val |= (bit << b)
            out[byte_idx] = byte_val
        witness = bytes(out)
    solver.delete()
    return PreimageResult(
        sat=bool(sat), witness=witness,
        n_vars=cnf.n_vars, n_clauses=len(cnf.clauses),
        encode_s=t1 - t0, bootstrap_s=t2 - t1, solve_s=t3 - t2,
        conflicts=stats.get("conflicts", 0),
        decisions=stats.get("decisions", 0),
        propagations=stats.get("propagations", 0),
        restarts=stats.get("restarts", 0),
    )


# ---------------------------------------------------------------------------
# Demo: quick smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import random
    random.seed(0)

    print("--- Variant A: free input bits ---")
    msg = b"The quick brown fox jumps over the lazy dog"
    h = hashlib.md5(msg).digest()
    target = [int.from_bytes(h[i:i+4], "little") for i in range(0, 16, 4)]
    for n in [0, 4, 8, 12, 16, 20]:
        free = random.sample(range(len(msg) * 8), n)
        r = solve_free_input(msg, free, target)
        match = (r.witness is not None and hashlib.md5(r.witness).digest() == h)
        print(f"  n={n:2d} sat={r.sat} match={match} "
              f"enc={r.encode_s*1000:5.0f}ms boot={r.bootstrap_s*1000:5.0f}ms "
              f"solve={r.solve_s*1000:7.1f}ms conf={r.conflicts:5d}")

    print("\n--- Variant B: k output bits constrained ---")
    for k in [4, 8, 12, 16, 20, 24]:
        # Use first k bits of md5("") for the target
        h0 = hashlib.md5(b"").digest()
        tgt = [int.from_bytes(h0[i:i+4], "little") for i in range(0, 16, 4)]
        r = solve_output_constrained(20, k, tgt)
        verify = ""
        if r.sat:
            got = hashlib.md5(r.witness).digest()
            got_word0 = int.from_bytes(got[:4], "little")
            tgt_word0 = tgt[0]
            mask = (1 << min(k, 32)) - 1
            verify = " match-low-k" if (got_word0 & mask) == (tgt_word0 & mask) else " MISMATCH"
        print(f"  k={k:3d} sat={r.sat}{verify} "
              f"enc={r.encode_s*1000:5.0f}ms boot={r.bootstrap_s*1000:5.0f}ms "
              f"solve={r.solve_s*1000:7.1f}ms conf={r.conflicts:5d}")
