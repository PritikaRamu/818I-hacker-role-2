#!/usr/bin/env python3
"""Build data/items.jsonl: six conditions (pre-registration) per patch from data/slices.json.

Runs src/extract_slices.py first, so the whole item set is regenerated from release/.
Usage: python3 src/build_items.py
"""
import json, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE / "perturb"))
import c3_rename, c4_comment, c5_decoy, c6_neutral  # noqa: E402

SLICES = ROOT / "data/slices.json"
OUT = ROOT / "data/items.jsonl"


def item(p, cond, base_cond, code, defended, pert):
    return {"item_id": f"{p['patch_id']}__{cond}", "patch_id": p["patch_id"], "cve": p["cve"],
            "vuln_type": p["vuln_type"], "condition": cond, "base_condition": base_cond,
            "base_code": p[base_cond], "code": code, "defense_present": defended,
            "defense_method": p["defense_method"], "sink_method": p["sink_method"], "perturbation": pert}


def none(desc):
    return {"type": "none", "renames": {}, "decoy_template": None, "decoy_var": None, "description": desc}


def main():
    subprocess.run([sys.executable, str(ROOT / "src/extract_slices.py")], check=True)
    patches = json.loads(SLICES.read_text())
    items = []
    for p in patches:
        items.append(item(p, "C1", "post", p["post"], True, none("Unmodified post-patch slice.")))
        items.append(item(p, "C2", "pre", p["pre"], False, none("Unmodified pre-patch slice.")))
        for cond, mod, base_cond, defended in (("C3", c3_rename, "pre", False), ("C4", c4_comment, "pre", False),
                                               ("C5", c5_decoy, "pre", False), ("C6", c6_neutral, "post", True)):
            try:
                code, pert = mod.make(p)
            except Exception as e:  # a generator that cannot handle a patch drops only that item
                print(f"[build] {p['patch_id']} {cond}: generator failed: {e!r}", file=sys.stderr)
                continue
            items.append(item(p, cond, base_cond, code, defended, pert))
    OUT.write_text("".join(json.dumps(it) + "\n" for it in items))
    print(f"[build] wrote {len(items)} items for {len(patches)} patches to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
