"""MD5 SAT preimage benchmark.

For each parameter value, run `samples` independent instances in isolated
worker processes (so a timeout can be enforced cleanly). Streams to CSV.

Variants:
  A. free_input  — vary n (number of free message bits).  Always SAT.
  B. output_bits — vary k (number of MD5 output bits constrained to a target).
                   May be SAT or UNSAT.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import multiprocessing as mp
import random
import sys
import time
from pathlib import Path


# Per-instance fixed message used for variant A.  55 bytes => fits one block.
DEFAULT_MSG = b"The quick brown fox jumps over the lazy dog. md5sat"
assert len(DEFAULT_MSG) <= 55


def _worker_free_input(args, conn) -> None:
    """Variant A worker."""
    message, free, target = args
    from preimage_sat import solve_free_input
    r = solve_free_input(message, free, target)
    conn.send(_to_dict(r))
    conn.close()


def _worker_output_bits(args, conn) -> None:
    """Variant B worker."""
    message_len, k, target = args
    from preimage_sat import solve_output_constrained
    r = solve_output_constrained(message_len, k, target)
    conn.send(_to_dict(r))
    conn.close()


def _to_dict(r) -> dict:
    return {
        "sat": r.sat,
        "n_vars": r.n_vars,
        "n_clauses": r.n_clauses,
        "encode_s": r.encode_s,
        "bootstrap_s": r.bootstrap_s,
        "solve_s": r.solve_s,
        "conflicts": r.conflicts,
        "decisions": r.decisions,
        "propagations": r.propagations,
        "restarts": r.restarts,
        "witness_hex": r.witness.hex() if r.witness else None,
    }


def run_one(worker, args, timeout: float) -> dict:
    parent_conn, child_conn = mp.Pipe()
    p = mp.Process(target=worker, args=(args, child_conn))
    t = time.perf_counter()
    p.start()
    p.join(timeout)
    wall = time.perf_counter() - t
    if p.is_alive():
        p.terminate(); p.join(2.0)
        if p.is_alive():
            p.kill()
        return {"timeout": True, "wall_s": wall}
    if parent_conn.poll():
        try:
            r = parent_conn.recv()
        except EOFError:
            return {"error": "no result", "wall_s": wall, "timeout": False}
        r["wall_s"] = wall
        r["timeout"] = False
        return r
    return {"error": f"exitcode={p.exitcode}", "wall_s": wall, "timeout": False}


def fmt(r: dict) -> str:
    if r.get("timeout"):
        return f"TIMEOUT after {r['wall_s']:.1f}s"
    if "error" in r:
        return f"ERROR ({r['error']})"
    return (f"{'SAT  ' if r['sat'] else 'UNSAT'} "
            f"enc={r['encode_s']*1000:5.0f}ms boot={r['bootstrap_s']*1000:5.0f}ms "
            f"solve={r['solve_s']*1000:9.1f}ms "
            f"conf={r['conflicts']:7d} dec={r['decisions']:8d} prop={r['propagations']:>12d}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", choices=["A", "B"], required=True,
                    help="A=free input bits, B=output bits constrained")
    ap.add_argument("--params", type=str, required=True,
                    help="comma-separated parameter values (n for A, k for B)")
    ap.add_argument("--samples", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--message-len", type=int, default=20,
                    help="for variant B, message length in bytes (default 20)")
    ap.add_argument("--out", type=str, required=True)
    ap.add_argument("--seed", type=int, default=20260524)
    args = ap.parse_args()

    params = [int(p) for p in args.params.split(",")]
    rng = random.Random(args.seed)

    msg = DEFAULT_MSG
    h = hashlib.md5(msg).digest()
    target_full = [int.from_bytes(h[i:i+4], "little") for i in range(0, 16, 4)]

    out_path = Path(args.out)
    new_file = not out_path.exists()
    f = out_path.open("a", newline="")
    cols = ["variant", "param", "sample", "n_vars", "n_clauses",
            "encode_s", "bootstrap_s", "solve_s", "wall_s",
            "sat", "conflicts", "decisions", "propagations", "restarts",
            "witness_hex", "timeout", "extra"]
    w = csv.DictWriter(f, fieldnames=cols)
    if new_file:
        w.writeheader()

    print(f"# variant={args.variant} params={params} samples={args.samples} timeout={args.timeout}s")
    for p in params:
        consec_timeouts = 0
        for s in range(args.samples):
            extra = ""
            if args.variant == "A":
                free = rng.sample(range(len(msg) * 8), p) if p > 0 else []
                wargs = (msg, free, target_full)
                worker = _worker_free_input
                extra = f"free_positions={','.join(map(str, sorted(free)))}"
            else:
                # For variant B we want each sample to have a different target.
                # Generate a random short message and hash IT, then constrain k bits.
                rand_msg = bytes(rng.randint(0, 255) for _ in range(args.message_len))
                h_r = hashlib.md5(rand_msg).digest()
                tgt = [int.from_bytes(h_r[i:i+4], "little") for i in range(0, 16, 4)]
                wargs = (args.message_len, p, tgt)
                worker = _worker_output_bits
                extra = f"target_hash={h_r.hex()}"
            r = run_one(worker, wargs, args.timeout)
            print(f"{args.variant}={p:3d} #{s}: {fmt(r)}", flush=True)
            row = {"variant": args.variant, "param": p, "sample": s,
                   "timeout": r.get("timeout", False), "wall_s": r.get("wall_s"),
                   "extra": extra}
            for c in ("n_vars", "n_clauses", "encode_s", "bootstrap_s", "solve_s",
                      "sat", "conflicts", "decisions", "propagations",
                      "restarts", "witness_hex"):
                if c in r:
                    row[c] = r[c]
            w.writerow(row); f.flush()
            if r.get("timeout"):
                consec_timeouts += 1
                if consec_timeouts >= 2:
                    print(f"  -- 2 timeouts at param={p}; skipping rest of this bucket")
                    break
            else:
                consec_timeouts = 0
    f.close()
    print(f"\nWrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
