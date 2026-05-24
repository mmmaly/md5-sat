"""Tseitin CNF encoder + 32-bit word primitives for MD5.

Word = list of 32 CNF variable IDs (literals), index 0 = LSB.
A literal may also be one of the two reserved constants TRUE / FALSE.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class CNF:
    clauses: list[list[int]] = field(default_factory=list)
    n_vars: int = 0
    TRUE: int = 0
    FALSE: int = 0

    def __post_init__(self) -> None:
        self.TRUE = self.new_var()
        self.FALSE = self.new_var()
        self.clauses.append([self.TRUE])
        self.clauses.append([-self.FALSE])

    # -- core ---------------------------------------------------------------

    def new_var(self) -> int:
        self.n_vars += 1
        return self.n_vars

    def add_clause(self, clause: list[int]) -> None:
        self.clauses.append(clause)

    def fresh_word(self) -> list[int]:
        return [self.new_var() for _ in range(32)]

    def const_word(self, value: int) -> list[int]:
        return [self.TRUE if (value >> i) & 1 else self.FALSE for i in range(32)]

    # -- gates with constant folding ---------------------------------------

    def neg(self, a: int) -> int:
        if a == self.TRUE:
            return self.FALSE
        if a == self.FALSE:
            return self.TRUE
        return -a

    def land(self, a: int, b: int) -> int:
        if a == self.FALSE or b == self.FALSE:
            return self.FALSE
        if a == self.TRUE:
            return b
        if b == self.TRUE:
            return a
        if a == b:
            return a
        if a == -b:
            return self.FALSE
        c = self.new_var()
        self.clauses.append([-a, -b, c])
        self.clauses.append([a, -c])
        self.clauses.append([b, -c])
        return c

    def lor(self, a: int, b: int) -> int:
        if a == self.TRUE or b == self.TRUE:
            return self.TRUE
        if a == self.FALSE:
            return b
        if b == self.FALSE:
            return a
        if a == b:
            return a
        if a == -b:
            return self.TRUE
        c = self.new_var()
        self.clauses.append([a, b, -c])
        self.clauses.append([-a, c])
        self.clauses.append([-b, c])
        return c

    def lxor(self, a: int, b: int) -> int:
        if a == self.FALSE:
            return b
        if b == self.FALSE:
            return a
        if a == self.TRUE:
            return self.neg(b)
        if b == self.TRUE:
            return self.neg(a)
        if a == b:
            return self.FALSE
        if a == -b:
            return self.TRUE
        c = self.new_var()
        self.clauses.append([-a, -b, -c])
        self.clauses.append([a, b, -c])
        self.clauses.append([a, -b, c])
        self.clauses.append([-a, b, c])
        return c

    # -- adders ------------------------------------------------------------

    def full_adder(self, a: int, b: int, cin: int) -> tuple[int, int]:
        ab_x = self.lxor(a, b)
        s = self.lxor(ab_x, cin)
        ab_a = self.land(a, b)
        cin_abx = self.land(cin, ab_x)
        cout = self.lor(ab_a, cin_abx)
        return s, cout

    # -- 32-bit word operations -------------------------------------------

    def word_xor(self, a: list[int], b: list[int]) -> list[int]:
        return [self.lxor(a[i], b[i]) for i in range(32)]

    def word_and(self, a: list[int], b: list[int]) -> list[int]:
        return [self.land(a[i], b[i]) for i in range(32)]

    def word_or(self, a: list[int], b: list[int]) -> list[int]:
        return [self.lor(a[i], b[i]) for i in range(32)]

    def word_not(self, a: list[int]) -> list[int]:
        return [self.neg(x) for x in a]

    def word_rotl(self, a: list[int], n: int) -> list[int]:
        n %= 32
        # rotate-left by n: bit at position i moves to position (i+n) % 32
        # in our LSB-first convention: result[(i+n) % 32] = a[i]
        out = [None] * 32
        for i in range(32):
            out[(i + n) % 32] = a[i]
        return out  # type: ignore

    def word_add(self, a: list[int], b: list[int]) -> list[int]:
        """32-bit modular addition (drops final carry)."""
        out = []
        carry = self.FALSE
        for i in range(32):
            s, carry = self.full_adder(a[i], b[i], carry)
            out.append(s)
        return out

    def word_add_many(self, words: list[list[int]]) -> list[int]:
        """Sum a list of 32-bit words mod 2^32."""
        acc = words[0]
        for w in words[1:]:
            acc = self.word_add(acc, w)
        return acc

    # -- helpers -----------------------------------------------------------

    def fix_word(self, word: list[int], value: int) -> None:
        for i, v in enumerate(word):
            bit = (value >> i) & 1
            if v == self.TRUE:
                if not bit:
                    raise ValueError("inconsistent fix: TRUE forced to 0")
                continue
            if v == self.FALSE:
                if bit:
                    raise ValueError("inconsistent fix: FALSE forced to 1")
                continue
            self.clauses.append([v if bit else -v])

    def fix_bit(self, lit: int, value: int) -> None:
        if lit == self.TRUE:
            if not value:
                raise ValueError("inconsistent")
            return
        if lit == self.FALSE:
            if value:
                raise ValueError("inconsistent")
            return
        self.clauses.append([lit if value else -lit])

    def word_value(self, word: list[int], model_set: set[int]) -> int:
        v = 0
        for i, lit in enumerate(word):
            if lit == self.TRUE:
                v |= (1 << i)
            elif lit == self.FALSE:
                pass
            elif lit > 0:
                if lit in model_set:
                    v |= (1 << i)
            else:  # negative literal
                if -lit not in model_set:
                    v |= (1 << i)
        return v
