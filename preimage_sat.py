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
from md5_cnf import md5_block_cnf
from sha1_cnf import sha1_block_cnf
from sha1_cnf import hash_words_to_bytes as sha1_hash_words_to_bytes


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
# Variant C: n-letter ASCII-lowercase string preimage
# ---------------------------------------------------------------------------

def _constrain_lowercase_letter(cnf: CNF, byte_lits: list[int]) -> None:
    """Constrain a list of 8 CNF literals (LSB first) to represent a byte in
    the range 0x61..0x7A (ASCII lowercase a..z).

    Bits 5, 6, 7 of every lowercase letter are 1, 1, 0 respectively, so we
    fix them as unit clauses. Bits 0..4 take 32 possible values; we have to
    forbid 6 of them: 0x00 (would give 0x60 == '`') and 0x1B..0x1F (would
    give 0x7B..0x7F). Each forbidden value adds one clause of length 5
    that asserts the AND of complements (i.e. at least one bit differs).
    """
    b0, b1, b2, b3, b4, b5, b6, b7 = byte_lits
    cnf.fix_bit(b5, 1)
    cnf.fix_bit(b6, 1)
    cnf.fix_bit(b7, 0)
    forbidden_lower5 = [0x00, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F]
    for val in forbidden_lower5:
        # clause: at least one of (b0..b4) differs from val
        clause = []
        for i, lit in enumerate([b0, b1, b2, b3, b4]):
            bit = (val >> i) & 1
            clause.append(cnf.neg(lit) if bit else lit)
        # filter out trivially-true literals (TRUE) — those make clause SAT for free
        if any(c == cnf.TRUE for c in clause):
            continue
        # drop FALSE literals (they don't help)
        clause = [c for c in clause if c != cnf.FALSE]
        if clause:
            cnf.add_clause(clause)


def build_letter_string_cnf(n_chars: int, target_hash_words: list[int]
                            ) -> tuple[CNF, list[list[int]], list[list[int]]]:
    """Build CNF: 'find an n_chars-letter lowercase ASCII string whose
    MD5 hash equals target_hash_words'.

    Implementation: allocate fresh CNF vars for all 8 bits of every input
    byte (so the encoder doesn't fold), constrain each input byte to a
    lowercase letter, then force the output to the target.
    """
    if n_chars < 0 or n_chars > 55:
        raise ValueError("n_chars must be in 0..55")
    cnf = CNF()
    zero_msg = bytes(n_chars)  # dummy; bits will be freed below
    free = list(range(n_chars * 8))
    block_words, hash_words = md5_cnf_from_bytes(cnf, zero_msg, free_bit_positions=free)
    # Constrain each input byte to be a lowercase ASCII letter.
    for byte_idx in range(n_chars):
        w_index = byte_idx // 4
        # bits (LSB first) of byte `byte_idx` are at positions [4*(byte_idx%4)*8 .. +8)
        # in word w_index? No — bit_in_word = (byte_idx % 4) * 8 + b for b in 0..7.
        # So byte_lits = block_words[w_index][offset..offset+8]
        offset = (byte_idx % 4) * 8
        byte_lits = block_words[w_index][offset:offset + 8]
        _constrain_lowercase_letter(cnf, byte_lits)
    # Force the output hash to the target.
    for word_idx, target_word in enumerate(target_hash_words):
        for bit_idx in range(32):
            lit = hash_words[word_idx][bit_idx]
            v = (target_word >> bit_idx) & 1
            cnf.fix_bit(lit, v)
    return cnf, block_words, hash_words


def solve_letter_string_preimage(n_chars: int,
                                  target_hash_words: list[int]) -> PreimageResult:
    t0 = time.perf_counter()
    cnf, block_words, _ = build_letter_string_cnf(n_chars, target_hash_words)
    t1 = time.perf_counter()
    solver = Cadical195(bootstrap_with=cnf.clauses)
    t2 = time.perf_counter()
    sat = solver.solve()
    t3 = time.perf_counter()
    stats = solver.accum_stats()
    witness: bytes | None = None
    if sat:
        model = set(solver.get_model())
        out = bytearray(n_chars)
        for byte_idx in range(n_chars):
            w_index = byte_idx // 4
            byte_val = 0
            for b in range(8):
                bit_in_word = (byte_idx % 4) * 8 + b
                lit = block_words[w_index][bit_in_word]
                if lit == cnf.TRUE: bit = 1
                elif lit == cnf.FALSE: bit = 0
                elif lit > 0: bit = 1 if lit in model else 0
                else: bit = 0 if -lit in model else 1
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
# Variant D: combined MD5 AND SHA-1 lowercase-string preimage
# ---------------------------------------------------------------------------

def _build_md5_block_from_msg_bits(cnf: CNF, msg_bytes_bits: list[list[int]]) -> list[list[int]]:
    """Build a 16-word MD5 input block from the given list of message bytes
    (each byte = 8 LSB-first literals). Pads with 0x80, zeros, and a
    little-endian 64-bit length suffix.
    """
    n = len(msg_bytes_bits)
    if n > 55:
        raise ValueError("≤55-byte messages only")
    block_words: list[list[int]] = []
    bit_len = n * 8
    pad_bytes = bytearray(64)
    # length-bytes will be little-endian for MD5
    length_le = bit_len.to_bytes(8, "little")
    for i in range(64):
        if i < n:
            pad_bytes[i] = 0  # placeholder, real bits come from msg_bytes_bits
        elif i == n:
            pad_bytes[i] = 0x80
        elif i < 56:
            pad_bytes[i] = 0x00
        else:
            pad_bytes[i] = length_le[i - 56]
    for w_index in range(16):
        word_literals = [cnf.FALSE] * 32
        for byte_in_word in range(4):
            byte_index = w_index * 4 + byte_in_word
            # In MD5 (little-endian), byte_in_word=0 is least-significant byte
            # → bits [0..7]; byte_in_word=1 → [8..15]; etc.
            base = byte_in_word * 8
            if byte_index < n:
                # use the actual msg bits
                for b in range(8):
                    word_literals[base + b] = msg_bytes_bits[byte_index][b]
            else:
                # constant byte
                v = pad_bytes[byte_index]
                for b in range(8):
                    word_literals[base + b] = cnf.TRUE if ((v >> b) & 1) else cnf.FALSE
        block_words.append(word_literals)
    return block_words


def _build_sha1_block_from_msg_bits(cnf: CNF, msg_bytes_bits: list[list[int]]) -> list[list[int]]:
    """Build a 16-word SHA-1 input block (big-endian byte order + big-endian
    length suffix) from the same list of message bytes."""
    n = len(msg_bytes_bits)
    if n > 55:
        raise ValueError("≤55-byte messages only")
    bit_len = n * 8
    pad_bytes = bytearray(64)
    length_be = bit_len.to_bytes(8, "big")
    for i in range(64):
        if i < n:
            pad_bytes[i] = 0
        elif i == n:
            pad_bytes[i] = 0x80
        elif i < 56:
            pad_bytes[i] = 0x00
        else:
            pad_bytes[i] = length_be[i - 56]
    block_words: list[list[int]] = []
    for w_index in range(16):
        word_literals = [cnf.FALSE] * 32
        for byte_in_word in range(4):
            byte_index = w_index * 4 + byte_in_word
            # SHA-1 big-endian: byte_in_word=0 is MOST significant byte →
            # bits [24..31]; byte_in_word=3 → [0..7].
            base = (3 - byte_in_word) * 8
            if byte_index < n:
                for b in range(8):
                    word_literals[base + b] = msg_bytes_bits[byte_index][b]
            else:
                v = pad_bytes[byte_index]
                for b in range(8):
                    word_literals[base + b] = cnf.TRUE if ((v >> b) & 1) else cnf.FALSE
        block_words.append(word_literals)
    return block_words


def build_combined_md5_sha1_letter_cnf(n_chars: int,
                                       target_md5_words: list[int],
                                       target_sha1_words: list[int]
                                       ) -> tuple[CNF, list[list[int]]]:
    """Build CNF: 'find n_chars lowercase letters whose MD5 hash equals
    target_md5_words AND whose SHA-1 hash equals target_sha1_words'.

    Returns (cnf, msg_bytes_bits). msg_bytes_bits[i] is the 8-literal
    LSB-first representation of byte i.
    """
    if n_chars < 0 or n_chars > 55:
        raise ValueError("0 ≤ n_chars ≤ 55")
    cnf = CNF()
    msg_bytes_bits = [[cnf.new_var() for _ in range(8)] for _ in range(n_chars)]
    for byte_lits in msg_bytes_bits:
        _constrain_lowercase_letter(cnf, byte_lits)
    # MD5
    md5_block = _build_md5_block_from_msg_bits(cnf, msg_bytes_bits)
    md5_hash = md5_block_cnf(cnf, md5_block)
    for word_idx, target_word in enumerate(target_md5_words):
        for bit_idx in range(32):
            cnf.fix_bit(md5_hash[word_idx][bit_idx], (target_word >> bit_idx) & 1)
    # SHA-1
    sha1_block = _build_sha1_block_from_msg_bits(cnf, msg_bytes_bits)
    sha1_hash = sha1_block_cnf(cnf, sha1_block)
    for word_idx, target_word in enumerate(target_sha1_words):
        for bit_idx in range(32):
            cnf.fix_bit(sha1_hash[word_idx][bit_idx], (target_word >> bit_idx) & 1)
    return cnf, msg_bytes_bits


def solve_combined_md5_sha1_letter(n_chars: int,
                                    target_md5_words: list[int],
                                    target_sha1_words: list[int]) -> PreimageResult:
    t0 = time.perf_counter()
    cnf, msg_bytes_bits = build_combined_md5_sha1_letter_cnf(
        n_chars, target_md5_words, target_sha1_words)
    t1 = time.perf_counter()
    solver = Cadical195(bootstrap_with=cnf.clauses)
    t2 = time.perf_counter()
    sat = solver.solve()
    t3 = time.perf_counter()
    stats = solver.accum_stats()
    witness: bytes | None = None
    if sat:
        model = set(solver.get_model())
        out = bytearray(n_chars)
        for byte_idx in range(n_chars):
            byte_val = 0
            for b in range(8):
                lit = msg_bytes_bits[byte_idx][b]
                if lit == cnf.TRUE: bit = 1
                elif lit == cnf.FALSE: bit = 0
                elif lit > 0: bit = 1 if lit in model else 0
                else: bit = 0 if -lit in model else 1
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
