# md5-sat

Same experiment style as [mmmaly/square-root-sat](https://github.com/mmmaly/square-root-sat),
but for **MD5**: encode the hash function as a CNF formula, throw it at a SAT
solver, and measure how solve time scales with how much we leave unknown.

## What we tried

1. **SAT solver.** [PySAT](https://pysathq.github.io/) + **Cadical 1.9.5**, same
   as the sqrt project.
2. **MD5 CNF encoder.** Full RFC-1321 MD5 for a single 512-bit block:
   - 64 rounds; round functions F / G / H / I as bitwise gates.
   - 32-bit modular adds via ripple-carry full-adders.
   - Left-rotation is free (just a literal-list permutation).
   - 64 K-constants and the IV are folded into the formula as TRUE/FALSE.
   - Padding (0x80 byte, zero fill, 64-bit length suffix) for arbitrary
     `≤55`-byte messages is folded the same way.
   - Per single-block MD5 instance: **~33k variables, ~112k clauses**.
3. **Two preimage variants** (both compared in parallel):
   - **A. Free input bits, parameter n.** Take a known 51-byte message `m`,
     fix the target hash to `md5(m)`, free `n` randomly-chosen bits of the
     message, fix the rest. Always SAT (the original bits are a witness).
     Tests *how many unknown input bits Cadical can find*.
   - **B. Constrained output bits, parameter k.** Leave the whole 20-byte
     message free; constrain only the first `k` bits of the hash to a target
     drawn from `md5(random)`. Smaller k → many collisions → easy SAT; larger
     k → genuine partial-preimage search.
4. **Verification.** `test_md5.py` encodes 24 random 0..55-byte messages with
   ALL input bits as free variables, forces them to the chosen bytes via
   unit clauses, decodes the four hash words from the SAT model, and checks
   against `hashlib.md5`. All 24 pass.
5. **Benchmark.** 8 samples per n (1..20), 5 samples per k (0..24), 300 s
   per-instance timeout, fork-isolated worker processes. Cadical's
   `conflicts`, `decisions`, `propagations`, `restarts` recorded alongside
   encoding / clause-loading / solve time.

## What we found

**TL;DR — Exponential growth in *both* directions. Heuristics do NOT
unlock MD5. This is the polar opposite of the sqrt result.**

### Variant A — free input bits

| n free | n inst | TO | conf median | conf max | solve median | solve max |
|---:|---:|---:|---:|---:|---:|---:|
|  1 | 8 | 0 |       0 |      0 | 0.0000 s | 0.0000 s |
|  2 | 8 | 0 |       0 |     70 | 0.006 s  | 0.011 s  |
|  4 | 8 | 0 |      79 |    570 | 0.025 s  | 0.038 s  |
|  6 | 8 | 0 |     423 |    809 | 0.083 s  | 0.146 s  |
|  8 | 8 | 0 |     723 |   1303 | 0.158 s  | 0.443 s  |
| 10 | 8 | 0 |   2 114 |  7 071 | 1.62 s   | 2.70 s   |
| 12 | 8 | 0 |   7 017 | 20 733 | 2.49 s   | 7.95 s   |
| 14 | 8 | 0 |  47 706 | 90 700 | 18.8 s   | 33.7 s   |
| 16 | 8 | 0 | 128 112 | 221 504| 53.0 s   | 100.5 s  |
| 18 | 3 | 3 | 313 930 | 433 395| 155 s    | 251 s    |
| 20 | 0 | 2 | — | — | — | — (both timed out at 300 s) |

### Variant B — output bits constrained

| k out | n inst | TO | conf median | conf max | solve median | solve max |
|---:|---:|---:|---:|---:|---:|---:|
|  0 | 5 | 0 |      0 |       0 | 0.003 s | 0.003 s |
|  4 | 5 | 0 |  1 009 |   1 009 | 0.134 s | 0.137 s |
|  8 | 5 | 0 |  2 063 |   2 599 | 2.40 s  | 4.86 s  |
| 12 | 5 | 0 | 11 244 |  45 764 | 10.5 s  | 16.1 s  |
| 16 | 4 | 1 |167 921 | 362 327 | 86.7 s  | 213 s   |
| 20 | 0 | 2 | — | — | — | — |
| 24 | 0 | 2 | — | — | — | — |

### Growth fits

|  | Exponential `t ~ 10^(b·p)` | Polynomial `t ~ p^c` |
|---|---|---|
| Variant A, solve   | **b = 0.348, doubling every 0.87 bits**, R² = 0.88 | c = 5.14, R² = 0.95 |
| Variant A, conflicts | **b = 0.321, doubling every 0.94 bits**, R² = 0.95 | c = 4.53, R² = 0.94 |
| Variant B, solve   | **b = 0.274, doubling every 1.10 bits**, R² = 0.97 | c = 4.49, R² = 0.98 |
| Variant B, conflicts | **b = 0.287, doubling every 1.05 bits**, R² = 0.88 | c = 3.40, R² = 0.81 |

The polynomial fits are mathematically a wash because the data only covers
a 20-bit range; the exponential reading is the natural one because:
- the encoding size is **constant** across the sweep (~33k vars, ~112k
  clauses always), and
- conflicts grow by **≈10× per 3 extra bits** in variant A and **≈10× per
  4 extra bits** in variant B — the textbook fingerprint of exponential
  search.

The naive baseline is `2^n` candidate inputs for variant A and `2^k` for a
partial preimage in variant B. Cadical's actual growth is roughly
**`~2^(n/0.94)` ≈ `2^(1.06·n)` conflicts** for variant A and `~2^(k/1.05)`
for variant B — i.e. Cadical does roughly as much work per bit as brute
search would, with the *constant factor* being the only thing the heuristics
help with.

## Contrast with mmmaly/square-root-sat

| | sqrt (`s·s = x`, k bits of x) | MD5 (n free input / k constrained output) |
|---|---|---|
| Encoding size | grows as O(k²): 16M vars / 58M clauses at k=512 | constant at ~33k vars / 112k clauses |
| SAT cases conflict count | **0 at every k from 16 to 512** | grows ~2× per free input bit |
| UNSAT conflict ceiling | **~1000 at every k from 64 to 512** | (variant B can grow indefinitely) |
| Growth in solve time | polynomial, ~k³–k⁴ — dominated by propagation length | **exponential, doubling every ~1 bit** |
| Hardest single instance | 1006 conflicts, 75 s at k=512 (16M vars) | 433 k conflicts, 251 s at n=18 (33k vars) |

The two projects together make a clean dichotomy: SAT heuristics tear
through the (highly structured) bit-blasted multiplier circuit but get no
traction on MD5's mixing network. That contrast is what cryptographic hash
functions are *designed* to produce.

## Files

| File | Role |
| --- | --- |
| `circuit.py` | Tseitin CNF encoder + 32-bit word ops (rotate-left, mod-2^32 add, AND/OR/XOR/NOT). |
| `md5_cnf.py` | One-block MD5: round constants, message-word permutation, the 64-round compression, IV finalization. Plus a pure-Python reference MD5 cross-check. |
| `test_md5.py` | Verifies the CNF MD5 agrees with `hashlib.md5` on 24 random messages. |
| `preimage_sat.py` | `solve_free_input(...)` and `solve_output_constrained(...)`. |
| `bench.py` | Driver: sweep parameter, samples-per-value, isolated workers + timeout. CSV streaming output. |
| `analyze.py` | Per-parameter summary table + exponential vs polynomial growth fits. |
| `plot.py` | Three log-y scatter plots (wall time, solve time, conflicts). |
| `results.csv` | Raw per-instance data from the benchmark. |

## How to run

```bash
pip install python-sat matplotlib

python3 test_md5.py

# Variant A: free input bits (always SAT)
python3 bench.py --variant A --params 1,2,4,6,8,10,12,14,16,18,20 \
        --samples 8 --timeout 300 --out results.csv

# Variant B: output bits constrained
python3 bench.py --variant B --params 0,4,8,12,16,20,24 \
        --samples 5 --timeout 300 --out results.csv

python3 analyze.py results.csv
python3 plot.py results.csv          # writes plot_*.png
```

## Caveats

- Single-block messages only (`≤55` bytes). Adding multi-block support is
  trivial in `md5_cnf.py` — chain blocks via the IV output of the previous
  one — but not required for the experiment.
- Cadical's default settings; no MD5-specific preprocessing (e.g.
  CryptoMiniSat's XOR detection, or SAT competition crypto-tuned configs)
  attempted.
- Variant A's "free bit positions" are sampled uniformly. Concentrating the
  free bits in particular message words would alter the difficulty
  distribution — interesting future direction.
