#!/usr/bin/env python3
"""Post-hoc audit of PRIMARY 'defended' judgments: classify what the qualifying variables name.
  sink_only  - every qualifying variable's method is the sink method itself
  invented   - no qualifying method is called anywhere in the item's code (comments excluded)
  in_code    - at least one qualifying method (not the sink) is called in the code
Also recomputes per-condition rates with sink_only judgments counted as not_defended (sensitivity only)."""
import json, re, collections
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
I = {json.loads(l)["item_id"]: json.loads(l) for l in (ROOT / "data/items.final.jsonl").read_text().splitlines() if l.strip()}
R = [json.loads(l) for l in (ROOT / "results/judgments.jsonl").read_text().splitlines() if l.strip()]
strip = lambda c: "\n".join(re.sub(r"//.*", "", l) for l in c.splitlines())
cls = collections.defaultdict(collections.Counter); sens = collections.defaultdict(lambda: [0, 0])
for r in R:
    if r["prompt_name"] != "PRIMARY" or r["judgment"] == "parse_fail":
        continue
    c = r["condition"]; it = I[r["item_id"]]; code = strip(it["code"])
    d = r["judgment"] == "defended"
    if d:
        ms = set()
        for v in r["parse_detail"].get("qualifying", []):
            ms |= {m for m in [v.get("related")] if m} | set(re.findall(r"\.(\w+)\s*\(", v["name"]))
        non_sink = ms - {it["sink_method"]}
        if ms and not non_sink:
            k = "sink_only"; d = False
        elif not any(re.search(r"\b" + re.escape(m) + r"\s*\(", code) for m in non_sink):
            k = "invented"
        else:
            k = "in_code"
        cls[c][k] += 1
    sens[c][0] += d; sens[c][1] += 1
for c in sorted(sens):
    print(c, dict(cls[c]), f"rate_without_sink_only={sens[c][0]}/{sens[c][1]}={sens[c][0]/sens[c][1]:.1%}")
