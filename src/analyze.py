#!/usr/bin/env python3
"""Metrics for the cue study (the pre-registration (REPORT.md §3) "Metrics"), per prompt_name, for T=0 samples and all samples pooled.

  python3 src/analyze.py [--in results/judgments.jsonl] [--out results]

- Rate for a condition = defended / (defended + not_defended); parse failures are excluded and
  reported separately per condition.
- 95% percentile bootstrap CIs, 2000 resamples, resampling PATCHES with replacement (seed 0).
- H1-H4: per-patch paired difference (rate in condition A minus rate in B for the same patch),
  averaged over patches that have usable judgments in both; bootstrap CI over patches.
Writes metrics.json, metrics_table.md and false_defense_by_condition.png into --out.
"""
import argparse, json, sys
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
CONDS = ["C1", "C2", "C3", "C4", "C5", "C6"]
RECOGNITION, FALSE_DEFENSE = ["C1", "C6"], ["C2", "C3", "C4", "C5"]
HYPOTHESES = {  # name: (A, B, metric); difference = A - B
    "H1_names": ("C3", "C2", "false-defense C3 - C2 (expected > 0)"),
    "H2_comments": ("C4", "C2", "false-defense C4 - C2 (expected > 0)"),
    "H3_presence_vs_effect": ("C5", "C2", "false-defense C5 - C2 (expected > 0)"),
    "H4_name_dependence": ("C1", "C6", "recognition C1 - C6 (expected > 0)"),
}
N_BOOT, SEED = 2000, 0


def counts_by_patch(rows):
    """{patch: {cond: [defended, valid, total]}}"""
    c = defaultdict(lambda: defaultdict(lambda: [0, 0, 0]))
    for r in rows:
        x = c[r["patch_id"]][r["condition"]]
        x[2] += 1
        if r["judgment"] != "parse_fail":
            x[1] += 1
            x[0] += r["judgment"] == "defended"
    return c


def pooled_rate(cbp, patches, cond):
    d = sum(cbp[p][cond][0] for p in patches if cond in cbp[p])
    v = sum(cbp[p][cond][1] for p in patches if cond in cbp[p])
    return d / v if v else None


def paired_diff(cbp, patches, a, b):
    diffs = []
    for p in patches:
        if a in cbp[p] and b in cbp[p] and cbp[p][a][1] and cbp[p][b][1]:
            diffs.append(cbp[p][a][0] / cbp[p][a][1] - cbp[p][b][0] / cbp[p][b][1])
    return (float(np.mean(diffs)) if diffs else None), len(diffs)


def ci(samples):
    s = [x for x in samples if x is not None]
    if not s:
        return [None, None]
    return [float(np.percentile(s, 2.5)), float(np.percentile(s, 97.5))]


def analyze(rows):
    cbp = counts_by_patch(rows)
    patches = sorted(cbp)
    rng = np.random.default_rng(SEED)
    boots = [list(rng.choice(patches, size=len(patches), replace=True)) for _ in range(N_BOOT)]
    out = {"n_patches": len(patches), "n_judgments": len(rows), "conditions": {}, "derived": {}, "hypotheses": {}}
    for c in CONDS:
        items = {r["item_id"] for r in rows if r["condition"] == c}
        tot = sum(cbp[p][c][2] for p in patches if c in cbp[p])
        val = sum(cbp[p][c][1] for p in patches if c in cbp[p])
        rate = pooled_rate(cbp, patches, c)
        out["conditions"][c] = {
            "metric": "recognition" if c in RECOGNITION else "false_defense",
            "rate_defended": rate, "ci95": ci([pooled_rate(cbp, b, c) for b in boots]),
            "n_items": len(items), "n_judgments": tot, "n_valid": val,
            "parse_fail_rate": (tot - val) / tot if tot else None}
    rate = lambda c, ps: pooled_rate(cbp, ps, c)
    for name, (a, b) in {"cue_susceptibility_C3": ("C3", "C2"), "cue_susceptibility_C4": ("C4", "C2"),
                         "cue_susceptibility_C5": ("C5", "C2"), "name_dependence": ("C1", "C6")}.items():
        f = lambda ps: (None if rate(a, ps) is None or rate(b, ps) is None else rate(a, ps) - rate(b, ps))
        out["derived"][name] = {"definition": f"rate({a}) - rate({b}), pooled over items",
                                "value": f(patches), "ci95": ci([f(bs) for bs in boots])}
    for h, (a, b, desc) in HYPOTHESES.items():
        val, n = paired_diff(cbp, patches, a, b)
        lo, hi = ci([paired_diff(cbp, bs, a, b)[0] for bs in boots])
        out["hypotheses"][h] = {"definition": desc + "; mean per-patch paired difference", "value": val,
                                "n_patches_paired": n, "ci95": [lo, hi],
                                "ci_excludes_0": None if lo is None else bool(lo > 0 or hi < 0)}
    pf = [v["parse_fail_rate"] for v in out["conditions"].values() if v["parse_fail_rate"] is not None]
    out["parse_fail_range"] = [min(pf), max(pf)] if pf else None
    return out


def agreement(rows):
    """PRIMARY vs NEUTRAL on the same (item, temperature, seed), both parsed."""
    by = defaultdict(dict)
    for r in rows:
        by[(r["item_id"], r["temperature"], r["seed"])][r["prompt_name"]] = r["judgment"]
    pairs = [(v["PRIMARY"], v["NEUTRAL"]) for v in by.values()
             if "PRIMARY" in v and "NEUTRAL" in v and "parse_fail" not in (v["PRIMARY"], v["NEUTRAL"])]
    if not pairs:
        return {"n_pairs": 0}
    agree = sum(a == b for a, b in pairs) / len(pairs)
    pa = sum(a == "defended" for a, _ in pairs) / len(pairs)
    pb = sum(b == "defended" for _, b in pairs) / len(pairs)
    pe = pa * pb + (1 - pa) * (1 - pb)
    return {"n_pairs": len(pairs), "percent_agreement": agree,
            "cohens_kappa": (agree - pe) / (1 - pe) if pe < 1 else None,
            "primary_defended_rate": pa, "neutral_defended_rate": pb}


def fmt(x, pct=True):
    return "n/a" if x is None else (f"{100 * x:.1f}%" if pct else f"{x:+.3f}")


def table(metrics):
    L = ["# Metrics (PROVISIONAL: pending human audit)", "",
         "Rates exclude parse failures. 95% CIs: 2000 bootstrap resamples of patches.", ""]
    for prompt, by_set in metrics["by_prompt"].items():
        for sset, m in by_set.items():
            L += [f"## {prompt} — {sset} ({m['n_patches']} patches, {m['n_judgments']} judgments)", "",
                  "| Condition | Metric | Rate judged defended | 95% CI | Items | Valid/total | Parse-fail |",
                  "|---|---|---|---|---|---|---|"]
            for c, v in m["conditions"].items():
                L.append(f"| {c} | {v['metric']} | {fmt(v['rate_defended'])} | [{fmt(v['ci95'][0])}, {fmt(v['ci95'][1])}] "
                         f"| {v['n_items']} | {v['n_valid']}/{v['n_judgments']} | {fmt(v['parse_fail_rate'])} |")
            L += ["", "| Derived | Value | 95% CI |", "|---|---|---|"]
            for k, v in m["derived"].items():
                L.append(f"| {k} | {fmt(v['value'], False)} | [{fmt(v['ci95'][0], False)}, {fmt(v['ci95'][1], False)}] |")
            L += ["", "| Hypothesis | Paired diff | 95% CI | Patches | CI excludes 0 |", "|---|---|---|---|---|"]
            for k, v in m["hypotheses"].items():
                L.append(f"| {k} | {fmt(v['value'], False)} | [{fmt(v['ci95'][0], False)}, {fmt(v['ci95'][1], False)}] "
                         f"| {v['n_patches_paired']} | {v['ci_excludes_0']} |")
            L.append("")
    L += ["## PRIMARY vs NEUTRAL agreement", ""]
    for sset, a in metrics["agreement"].items():
        L.append(f"- {sset}: " + ", ".join(f"{k}={fmt(v, k != 'n_pairs' and k != 'cohens_kappa') if isinstance(v, float) else v}"
                                          for k, v in a.items()))
    return "\n".join(L) + "\n"


def plot(metrics, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("[analyze] matplotlib not installed; skipping the bar chart", file=sys.stderr)
        return
    fig, ax = plt.subplots(figsize=(8, 4.2))
    prompts = list(metrics["by_prompt"])
    w = 0.8 / max(1, len(prompts))
    x = np.arange(len(CONDS))
    for i, p in enumerate(prompts):
        m = metrics["by_prompt"][p]["temperature_0"]["conditions"]
        vals = [m[c]["rate_defended"] if c in m and m[c]["rate_defended"] is not None else np.nan for c in CONDS]
        lo = [v - (m[c]["ci95"][0] if c in m and m[c]["ci95"][0] is not None else v) for c, v in zip(CONDS, vals)]
        hi = [(m[c]["ci95"][1] if c in m and m[c]["ci95"][1] is not None else v) - v for c, v in zip(CONDS, vals)]
        ax.bar(x + (i - (len(prompts) - 1) / 2) * w, vals, w, yerr=[lo, hi], capsize=3, label=p)
    ax.set_xticks(x, [f"{c}\n({'recog.' if c in RECOGNITION else 'false-def.'})" for c in CONDS])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Share judged \"defended\" (T=0)")
    ax.set_title("Judged defended by condition (C1, C6: defense present; C2–C5: absent)")
    ax.axvspan(0.5, 4.5, color="0.9", zorder=0)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=150)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default=str(ROOT / "results/judgments.jsonl"))
    ap.add_argument("--out", default=str(ROOT / "results"))
    args = ap.parse_args()
    rows = [json.loads(l) for l in Path(args.inp).read_text().splitlines() if l.strip()]
    if not rows:
        sys.exit(f"no rows in {args.inp}")
    sets = {"temperature_0": lambda r: r["temperature"] == 0, "all_samples_pooled": lambda r: True}
    metrics = {"input": args.inp, "by_prompt": {}, "agreement": {}}
    for p in sorted({r["prompt_name"] for r in rows}):
        metrics["by_prompt"][p] = {s: analyze([r for r in rows if r["prompt_name"] == p and f(r)]) for s, f in sets.items()}
    for s, f in sets.items():
        metrics["agreement"][s] = agreement([r for r in rows if f(r)])
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (out / "metrics_table.md").write_text(table(metrics))
    plot(metrics, out / "false_defense_by_condition.png")
    print(f"[analyze] wrote metrics.json, metrics_table.md, false_defense_by_condition.png to {out}")


if __name__ == "__main__":
    main()
