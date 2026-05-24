"""CNF encoder for one block of MD5 (RFC 1321).

`md5_block(cnf, block)`:
  block — list of 16 32-bit words (each a list of 32 CNF literals, LSB first),
          representing the 512-bit padded message block.
  returns: list of 4 32-bit words (A, B, C, D) representing the 128-bit hash
          (little-endian on disk: byte 0 = A_low_byte).

`md5_padded_block(message_bytes, cnf=None)`:
  Helper: takes a Python bytes message of length <=55, builds the padded
  512-bit block as a list of 16 words.  If `cnf` is given, returns words made
  of CNF literals (all bits set to TRUE/FALSE constants).  If cnf is None,
  returns words as plain ints (useful for the reference hash).

`reference_md5(message_bytes)`:
  Pure-Python MD5 over a 1-block (<=55 byte) message, returning the 128-bit
  hash as four 32-bit ints (A, B, C, D).  Used to cross-check the CNF
  encoder.
"""
from __future__ import annotations
import math

from circuit import CNF


# ---------------------------------------------------------------------------
# MD5 constants
# ---------------------------------------------------------------------------

K = [int(math.floor(abs(math.sin(i + 1)) * (1 << 32))) & 0xFFFFFFFF for i in range(64)]

S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]

IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]


def message_index(i: int) -> int:
    """Returns g(i) — which message word is consumed at round i."""
    if i < 16:
        return i
    if i < 32:
        return (5 * i + 1) % 16
    if i < 48:
        return (3 * i + 5) % 16
    return (7 * i) % 16


# ---------------------------------------------------------------------------
# Reference pure-Python MD5 (single 512-bit block)
# ---------------------------------------------------------------------------

def _rotl(x: int, n: int) -> int:
    n %= 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def reference_md5_block(block: list[int], iv: list[int] | None = None) -> list[int]:
    """Apply one MD5 compression to a single 512-bit block (16 words)."""
    if iv is None:
        iv = IV
    a, b, c, d = iv
    aa, bb, cc, dd = a, b, c, d
    for i in range(64):
        if i < 16:
            f = (b & c) | ((~b) & d) & 0xFFFFFFFF
        elif i < 32:
            f = (b & d) | (c & (~d & 0xFFFFFFFF))
        elif i < 48:
            f = b ^ c ^ d
        else:
            f = c ^ (b | (~d & 0xFFFFFFFF))
        f &= 0xFFFFFFFF
        temp = (a + f + K[i] + block[message_index(i)]) & 0xFFFFFFFF
        new_b = (b + _rotl(temp, S[i])) & 0xFFFFFFFF
        a, d, c, b = d, c, b, new_b
    return [(a + aa) & 0xFFFFFFFF,
            (b + bb) & 0xFFFFFFFF,
            (c + cc) & 0xFFFFFFFF,
            (d + dd) & 0xFFFFFFFF]


def pad_message_to_block(message: bytes) -> list[int]:
    """Pad a <=55-byte message to a 512-bit block (16 little-endian words)."""
    if len(message) > 55:
        raise ValueError("only single-block messages (<=55 bytes) supported")
    bit_len = len(message) * 8
    padded = bytearray(message)
    padded.append(0x80)
    while len(padded) < 56:
        padded.append(0x00)
    # 64-bit length, little-endian
    padded += bit_len.to_bytes(8, "little")
    assert len(padded) == 64
    return [int.from_bytes(padded[i:i+4], "little") for i in range(0, 64, 4)]


def reference_md5(message: bytes) -> bytes:
    """Compute MD5 over a single-block message; returns 16 bytes."""
    block = pad_message_to_block(message)
    out_words = reference_md5_block(block)
    return b"".join(w.to_bytes(4, "little") for w in out_words)


# ---------------------------------------------------------------------------
# CNF encoder
# ---------------------------------------------------------------------------

def md5_block_cnf(cnf: CNF, block: list[list[int]],
                  iv: list[list[int]] | None = None) -> list[list[int]]:
    """Encode one MD5 compression in CNF.

    `block`: list of 16 32-bit "words", each a list of 32 CNF literals (LSB
             first). Some literals may be the TRUE/FALSE constants, in which
             case the encoder folds aggressively.
    `iv`:    optional initial state of 4 words (defaults to MD5 IV constants).
    Returns the 4 output words.
    """
    if iv is None:
        iv = [cnf.const_word(v) for v in IV]
    a, b, c, d = iv
    aa, bb, cc, dd = a, b, c, d

    for i in range(64):
        if i < 16:
            # F = (B AND C) OR ((NOT B) AND D)
            f = cnf.word_or(cnf.word_and(b, c),
                            cnf.word_and(cnf.word_not(b), d))
        elif i < 32:
            # G = (B AND D) OR (C AND (NOT D))
            f = cnf.word_or(cnf.word_and(b, d),
                            cnf.word_and(c, cnf.word_not(d)))
        elif i < 48:
            # H = B XOR C XOR D
            f = cnf.word_xor(cnf.word_xor(b, c), d)
        else:
            # I = C XOR (B OR (NOT D))
            f = cnf.word_xor(c, cnf.word_or(b, cnf.word_not(d)))

        Kw = cnf.const_word(K[i])
        Mw = block[message_index(i)]
        # temp = a + f + K + M  (mod 2^32)
        temp = cnf.word_add_many([a, f, Kw, Mw])
        # rotate left by S[i]
        temp = cnf.word_rotl(temp, S[i])
        # new_b = b + temp
        new_b = cnf.word_add(b, temp)
        # rotate registers: A <- D, D <- C, C <- B, B <- new_b
        a, d, c, b = d, c, b, new_b

    return [cnf.word_add(a, aa),
            cnf.word_add(b, bb),
            cnf.word_add(c, cc),
            cnf.word_add(d, dd)]


def md5_cnf_from_bytes(cnf: CNF, message: bytes,
                       free_bit_positions: list[int] | None = None
                       ) -> tuple[list[list[int]], list[list[int]]]:
    """Build the CNF for md5(message), where `free_bit_positions` are bit
    indices of the *original message* (0..len(message)*8) that should be free
    SAT variables instead of constants. All other bits — including the
    0x80-pad byte, zero padding, and length suffix — are fixed.

    Returns (block_words, hash_words). block_words are the 16 padded message
    words (each a list of 32 literals); hash_words are the 4 output words.
    """
    if free_bit_positions is None:
        free_bit_positions = []
    free_set = set(free_bit_positions)
    msg_bits = len(message) * 8
    bit_len = msg_bits
    # Build padded message as a 64-byte bytearray
    padded = bytearray(message)
    padded.append(0x80)
    while len(padded) < 56:
        padded.append(0x00)
    padded += bit_len.to_bytes(8, "little")
    assert len(padded) == 64

    # Build 16 words of 32 literals each.  Bits in original-message positions
    # that are in free_set become fresh CNF vars; everything else is constant.
    block_words: list[list[int]] = []
    for w_index in range(16):
        word_literals = []
        for bit_in_word in range(32):
            # Which byte and bit?
            byte_index = w_index * 4 + (bit_in_word // 8)
            bit_in_byte = bit_in_word % 8
            # Absolute bit position in the *original* message (before pad)
            abs_bit = byte_index * 8 + bit_in_byte
            if abs_bit < msg_bits and abs_bit in free_set:
                word_literals.append(cnf.new_var())
            else:
                v = (padded[byte_index] >> bit_in_byte) & 1
                word_literals.append(cnf.TRUE if v else cnf.FALSE)
        block_words.append(word_literals)
    hash_words = md5_block_cnf(cnf, block_words)
    return block_words, hash_words


def hash_words_to_bytes(words: list[int]) -> bytes:
    return b"".join(w.to_bytes(4, "little") for w in words)
