"""Summarise MD5 SAT preimage bench results and fit growth curves.

For each variant and parameter value:
  - n samples, n timeouts
  - median / max wall time, solve time
  - median / max Cadical conflicts and decisions
  - whether *any* instance was solved by preprocessing alone

Then fits log10(median solve_s) vs param:
  - exponential:   log10 t = a + b*p     -> t ~ 10^(b*p)
  - polynomial:    log10 t = a + b*log10(p) -> t ~ p^b
and reports R^2 for each.
"""
from __future__ import annotations
import csv
import math
import statistics
import sys
from collections import defaultdict


def fit_linear(xs, ys):
    n = len(xs)
    if n < 2:
        return float("nan"), float("nan"), float("nan")
    mx = sum(xs) / n; my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    syy = sum((y - my) ** 2 for y in ys)
    if sxx == 0: return float("nan"), float("nan"), float("nan")
    b = sxy / sxx; a = my - b * mx
    ss_res = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
    r2 = 1 - ss_res / syy if syy > 0 else float("nan")
    return a, b, r2


def main(path: str = "results.csv") -> int:
    rows = []
    with open(path) as f:
        for row in csv.DictReader(f):
            rows.append(row)
    if not rows:
        print("no rows"); return 1

    groups = defaultdict(list)
    for row in rows:
        groups[(row["variant"], int(row["param"]))].append(row)

    by_variant = defaultdict(list)
    print(f"{'var':>3} {'p':>4} {'n':>3} {'TO':>3} "
          f"{'vars':>9} {'clauses':>10} "
          f"{'wall_med':>10} {'wall_max':>10} "
          f"{'solve_med':>11} {'solve_max':>11} "
          f"{'conf_med':>10} {'conf_max':>10} "
          f"{'searched':>9} {'sat_rate':>9}")
    print("-" * 140)
    for (variant, p), items in sorted(groups.items()):
        timeouts = [it for it in items if it["timeout"] == "True"]
        ok = [it for it in items if it["timeout"] != "True" and it.get("n_vars")]
        n_vars = ok[0]["n_vars"] if ok else "?"
        n_cl = ok[0]["n_clauses"] if ok else "?"
        walls = [float(it["wall_s"]) for it in ok]
        solves = [float(it["solve_s"]) for it in ok]
        confs = [int(it["conflicts"]) for it in ok]
        sats = [it["sat"] == "True" for it in ok]
        searched = sum(1 for c in confs if c > 0)
        wmed = statistics.median(walls) if walls else float("nan")
        wmax = max(walls) if walls else float("nan")
        smed = statistics.median(solves) if solves else float("nan")
        smax = max(solves) if solves else float("nan")
        cmed = statistics.median(confs) if confs else float("nan")
        cmax = max(confs) if confs else 0
        sat_rate = (sum(sats) / len(sats)) if sats else float("nan")
        print(f"{variant:>3} {p:4d} {len(ok):3d} {len(timeouts):3d} "
              f"{n_vars:>9} {n_cl:>10} "
              f"{wmed:>10.3f} {wmax:>10.3f} "
              f"{smed:>11.4f} {smax:>11.4f} "
              f"{cmed:>10.0f} {cmax:>10d} "
              f"{searched:>3d}/{len(ok):<3d}  {sat_rate*100:>6.1f}%")
        if walls:
            by_variant[variant].append((p, statistics.median(walls), statistics.median(solves), cmed))

    print()
    print("Growth fits (log10 median TIME vs param):")
    for variant, pts in by_variant.items():
        ps = [p for p, w, s, c in pts]
        wmeds = [max(w, 1e-6) for p, w, s, c in pts]
        smeds = [max(s, 1e-6) for p, w, s, c in pts]
        cmeds = [max(c, 1) for p, w, s, c in pts]
        if len(ps) < 3: continue
        log_w = [math.log10(w) for w in wmeds]
        log_s = [math.log10(s) for s in smeds]
        log_c = [math.log10(c) for c in cmeds]
        log_p = [math.log10(p) if p > 0 else float("nan") for p in ps]
        # exclude p=0 from polynomial fit
        ps_pos = [p for p in ps if p > 0]
        log_p_pos = [math.log10(p) for p in ps_pos]
        log_w_pos = [log_w[i] for i, p in enumerate(ps) if p > 0]
        log_s_pos = [log_s[i] for i, p in enumerate(ps) if p > 0]
        log_c_pos = [log_c[i] for i, p in enumerate(ps) if p > 0]

        def report(label, ys, ys_pos):
            ae, be, r2e = fit_linear(ps, ys)
            ap, bp, r2p = fit_linear(log_p_pos, ys_pos)
            print(f"  {label}:")
            print(f"    exponential  log10 t = {ae:7.3f} + {be:7.4f} * p   "
                  f"=>  t ~ 10^({be:.4f} * p)         doubling every {0.30103/be:7.2f} (if b>0)  R^2 = {r2e:.3f}"
                  if be > 0 else f"    exponential  log10 t = {ae:7.3f} + {be:7.4f} * p   R^2 = {r2e:.3f}")
            print(f"    polynomial   log10 t = {ap:7.3f} + {bp:7.4f} * log10(p)   =>  t ~ p^{bp:.3f}                 R^2 = {r2p:.3f}")

        print(f"\n  variant {variant}, wall:")
        report("wall_med", log_w, log_w_pos)
        print(f"  variant {variant}, solve:")
        report("solve_med", log_s, log_s_pos)
        print(f"  variant {variant}, conflicts:")
        report("conf_med", log_c, log_c_pos)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "results.csv"))
