"""Render MD5 bench results: wall time, solve time, conflicts vs parameter.

Three log-y scatter plots per variant.
"""
from __future__ import annotations
import csv
import sys
from collections import defaultdict


def load(path):
    rows = []
    with open(path) as f:
        for row in csv.DictReader(f):
            if row["timeout"] == "True":
                rows.append({"variant": row["variant"],
                             "param": int(row["param"]),
                             "wall_s": float(row["wall_s"]),
                             "timeout": True})
                continue
            if not row.get("n_vars"):
                continue
            rows.append({
                "variant": row["variant"],
                "param": int(row["param"]),
                "wall_s": float(row["wall_s"]),
                "solve_s": float(row["solve_s"]),
                "bootstrap_s": float(row["bootstrap_s"]),
                "encode_s": float(row["encode_s"]),
                "conflicts": int(row["conflicts"]),
                "decisions": int(row["decisions"]),
                "sat": row["sat"] == "True",
                "timeout": False,
            })
    return rows


def main() -> int:
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping plots", file=sys.stderr)
        return 0
    path = sys.argv[1] if len(sys.argv) > 1 else "results.csv"
    rows = load(path)
    by_variant = defaultdict(list)
    for r in rows:
        by_variant[r["variant"]].append(r)
    labels = {"A": "Variant A: free input bits", "B": "Variant B: output bits constrained"}
    colors = {"A": "C0", "B": "C3"}

    # plot 1: wall_s
    fig, ax = plt.subplots(figsize=(8, 5))
    for v, items in by_variant.items():
        xs = [it["param"] for it in items if not it["timeout"]]
        ys = [it["wall_s"] for it in items if not it["timeout"]]
        ax.scatter(xs, ys, c=colors.get(v, "k"), alpha=0.7, label=labels.get(v, v))
        # mark timeouts
        xs_to = [it["param"] for it in items if it["timeout"]]
        ys_to = [it["wall_s"] for it in items if it["timeout"]]
        if xs_to:
            ax.scatter(xs_to, ys_to, c=colors.get(v, "k"), marker="x", s=80,
                       label=f"{labels.get(v, v)} (timeout)")
    ax.set_xlabel("parameter (n free input bits, or k output bits constrained)")
    ax.set_ylabel("wall-clock time (s)")
    ax.set_yscale("log")
    ax.set_title("MD5 SAT preimage: total time vs parameter")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend()
    fig.tight_layout(); fig.savefig("plot_wall_time.png", dpi=140)
    print("wrote plot_wall_time.png")

    # plot 2: solve_s alone
    fig, ax = plt.subplots(figsize=(8, 5))
    for v, items in by_variant.items():
        xs = [it["param"] for it in items if not it["timeout"]]
        ys = [max(it["solve_s"], 1e-6) for it in items if not it["timeout"]]
        ax.scatter(xs, ys, c=colors.get(v, "k"), alpha=0.7, label=labels.get(v, v))
    ax.set_xlabel("parameter")
    ax.set_ylabel("Cadical solve() time (s, 1µs floor)")
    ax.set_yscale("log")
    ax.set_title("MD5 SAT preimage: pure solve time")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend()
    fig.tight_layout(); fig.savefig("plot_solve_time.png", dpi=140)
    print("wrote plot_solve_time.png")

    # plot 3: conflicts
    fig, ax = plt.subplots(figsize=(8, 5))
    for v, items in by_variant.items():
        xs = [it["param"] for it in items if not it["timeout"]]
        ys = [max(it["conflicts"], 1) for it in items if not it["timeout"]]
        ax.scatter(xs, ys, c=colors.get(v, "k"), alpha=0.7, label=labels.get(v, v))
    ax.set_xlabel("parameter")
    ax.set_ylabel("Cadical conflicts (1 floor)")
    ax.set_yscale("log")
    ax.set_title("MD5 SAT preimage: CDCL conflicts per instance")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend()
    fig.tight_layout(); fig.savefig("plot_conflicts.png", dpi=140)
    print("wrote plot_conflicts.png")
    return 0


if __name__ == "__main__":
    sys.exit(main())
