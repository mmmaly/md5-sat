"""CNF encoder for one block of SHA-1 (FIPS 180-4).

Public API:

  reference_sha1(message_bytes) -> bytes
      Pure-Python SHA-1 for messages of length ≤55 bytes (single block).

  sha1_block_cnf(cnf, block_words, iv=None) -> list[5 words]
      Encode one SHA-1 compression in CNF. block_words is 16 32-bit "words"
      (each a list of 32 CNF literals, LSB first). Returns 5 output words
      (A,B,C,D,E) — also LSB-first inside each word.

  sha1_cnf_from_bytes(cnf, message, free_bit_positions=None)
      -> (block_words, hash_words)
      Build the padded block from a Python `bytes` message, with some bit
      positions (indexed by abs-bit-in-message, MSB-first within each byte to
      match SHA-1's big-endian convention — see code) optionally left free.

Conventions:
  - A CNF "word" is a list of 32 literals, index i = bit value 2^i (LSB at
    index 0). This matches md5_cnf.py.
  - SHA-1 is *big-endian* both in how it views message bytes (byte 0 of the
    block is the MSB of word 0) and in how it serializes the output. We
    translate at the byte<->word boundary; everything inside the round
    function works on plain little-endian 32-bit words.
"""
from __future__ import annotations

from circuit import CNF


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

K_ROUND = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]


def _K(t: int) -> int:
    return K_ROUND[t // 20]


# ---------------------------------------------------------------------------
# Pure-Python reference
# ---------------------------------------------------------------------------

def _rotl(x: int, n: int) -> int:
    n %= 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def reference_sha1_block(block: list[int], iv: list[int] | None = None) -> list[int]:
    if iv is None:
        iv = IV
    # Expand 16 words to 80.
    W = list(block)
    for t in range(16, 80):
        W.append(_rotl(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1))
    a, b, c, d, e = iv
    aa, bb, cc, dd, ee = a, b, c, d, e
    for t in range(80):
        if t < 20:
            f = (b & c) | ((~b & 0xFFFFFFFF) & d)
        elif t < 40:
            f = b ^ c ^ d
        elif t < 60:
            f = (b & c) | (b & d) | (c & d)
        else:
            f = b ^ c ^ d
        temp = (_rotl(a, 5) + f + e + _K(t) + W[t]) & 0xFFFFFFFF
        e = d; d = c; c = _rotl(b, 30); b = a; a = temp
    return [(a + aa) & 0xFFFFFFFF,
            (b + bb) & 0xFFFFFFFF,
            (c + cc) & 0xFFFFFFFF,
            (d + dd) & 0xFFFFFFFF,
            (e + ee) & 0xFFFFFFFF]


def pad_message_to_block(message: bytes) -> list[int]:
    """Pad a ≤55-byte message to a 512-bit block (16 big-endian words)."""
    if len(message) > 55:
        raise ValueError("only single-block messages (≤55 bytes) supported")
    bit_len = len(message) * 8
    padded = bytearray(message)
    padded.append(0x80)
    while len(padded) < 56:
        padded.append(0x00)
    padded += bit_len.to_bytes(8, "big")
    assert len(padded) == 64
    # SHA-1 reads each 4-byte group as a BIG-ENDIAN 32-bit word.
    return [int.from_bytes(padded[i:i+4], "big") for i in range(0, 64, 4)]


def reference_sha1(message: bytes) -> bytes:
    block = pad_message_to_block(message)
    out = reference_sha1_block(block)
    # Output is concatenation of 5 words in BIG-ENDIAN byte order.
    return b"".join(w.to_bytes(4, "big") for w in out)


# ---------------------------------------------------------------------------
# CNF encoder
# ---------------------------------------------------------------------------

def sha1_block_cnf(cnf: CNF, block: list[list[int]],
                   iv: list[list[int]] | None = None) -> list[list[int]]:
    """Encode one SHA-1 compression in CNF.

    `block`: list of 16 words (each 32 literals, LSB-first internal layout).
             How the message bytes map into bit positions of these words is
             the caller's responsibility — see sha1_cnf_from_bytes.
    `iv`:    optional 5-word initial state (defaults to SHA-1 IV constants).
    Returns 5 output words (A,B,C,D,E) — also LSB-first inside each word.
    """
    if iv is None:
        iv = [cnf.const_word(v) for v in IV]
    a, b, c, d, e = iv
    aa, bb, cc, dd, ee = a, b, c, d, e

    # Expand 16 words to 80.
    W = list(block)
    for t in range(16, 80):
        # W[t] = rotl1(W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16])
        x = cnf.word_xor(W[t-3], W[t-8])
        x = cnf.word_xor(x, W[t-14])
        x = cnf.word_xor(x, W[t-16])
        W.append(cnf.word_rotl(x, 1))

    for t in range(80):
        if t < 20:
            # f = (b AND c) OR ((NOT b) AND d)
            f = cnf.word_or(cnf.word_and(b, c),
                            cnf.word_and(cnf.word_not(b), d))
        elif t < 40:
            f = cnf.word_xor(cnf.word_xor(b, c), d)
        elif t < 60:
            # f = (b AND c) OR (b AND d) OR (c AND d) — majority
            f = cnf.word_or(cnf.word_or(cnf.word_and(b, c),
                                        cnf.word_and(b, d)),
                            cnf.word_and(c, d))
        else:
            f = cnf.word_xor(cnf.word_xor(b, c), d)

        Kw = cnf.const_word(_K(t))
        # temp = rotl5(a) + f + e + K + W[t]
        a_rotl5 = cnf.word_rotl(a, 5)
        temp = cnf.word_add_many([a_rotl5, f, e, Kw, W[t]])
        # e <- d; d <- c; c <- rotl30(b); b <- a; a <- temp
        new_c = cnf.word_rotl(b, 30)
        e, d, c, b, a = d, c, new_c, a, temp

    return [cnf.word_add(a, aa),
            cnf.word_add(b, bb),
            cnf.word_add(c, cc),
            cnf.word_add(d, dd),
            cnf.word_add(e, ee)]


def sha1_cnf_from_bytes(cnf: CNF, message: bytes,
                        free_bit_positions: list[int] | None = None
                        ) -> tuple[list[list[int]], list[list[int]]]:
    """Build the SHA-1 CNF for a single-block message.

    `free_bit_positions` is a list of bit positions of the ORIGINAL MESSAGE
    (numbered 0..len(message)*8-1 in **LSB-first byte order**, i.e. abs_bit
    = byte_index * 8 + bit_in_byte, where bit_in_byte = 0 is the LSB of that
    byte) that should be free CNF variables. Everything else (the rest of
    the message, the 0x80 pad byte, zero pad, and the BIG-ENDIAN length
    suffix) becomes constants. Using LSB-first matches md5_cnf.py exactly,
    so the same `free_bit_positions` list designates the same bits in both
    encoders.

    Returns (block_words, hash_words).  Both lists hold 32 literals each in
    the internal LSB-first layout. block_words is 16 words; hash_words is 5
    words. The byte ordering of the original message is handled internally:
    SHA-1 puts byte 0 at the high-order byte of W[0], whereas MD5 puts it at
    the low-order byte; the bit-of-byte i.e. LSB/MSB within each BYTE is
    the same in both.
    """
    if free_bit_positions is None:
        free_bit_positions = []
    free_set = set(free_bit_positions)
    msg_bits = len(message) * 8
    bit_len = msg_bits
    padded = bytearray(message)
    padded.append(0x80)
    while len(padded) < 56:
        padded.append(0x00)
    padded += bit_len.to_bytes(8, "big")   # big-endian length suffix
    assert len(padded) == 64

    # Build 16 words.  SHA-1 word W[w_index] reads bytes [w*4, w*4+1, w*4+2,
    # w*4+3] of the block in BIG-ENDIAN order — i.e. byte (w*4) is the
    # most-significant byte (bits 24..31 of our LSB-first word).
    block_words: list[list[int]] = []
    for w_index in range(16):
        word_literals = [cnf.FALSE] * 32
        for byte_in_word in range(4):
            byte_index = w_index * 4 + byte_in_word
            byte_value = padded[byte_index]
            # In big-endian layout, byte_in_word=0 is the most significant
            # byte → occupies bit positions [24..31] of the word.
            # byte_in_word=1 occupies [16..23], etc.
            base = (3 - byte_in_word) * 8
            for b in range(8):  # b = bit_in_byte (LSB-first within the byte)
                pos = base + b
                # Original-message bit identity
                abs_bit = byte_index * 8 + b
                if abs_bit < msg_bits and abs_bit in free_set:
                    word_literals[pos] = cnf.new_var()
                else:
                    bit_val = (byte_value >> b) & 1
                    word_literals[pos] = cnf.TRUE if bit_val else cnf.FALSE
        block_words.append(word_literals)

    hash_words = sha1_block_cnf(cnf, block_words)
    return block_words, hash_words


def hash_words_to_bytes(words: list[int]) -> bytes:
    """Serialise SHA-1 output: 5 words in BIG-ENDIAN, concatenated."""
    return b"".join(w.to_bytes(4, "big") for w in words)
