#!/usr/bin/env python3
"""Mechanical validator for the perturbation set.

Written independently of the Claude Code session that generates the items, and
write-protected from it, so the generator cannot grade its own work.

Input : data/items.jsonl (schema: see data/items.final.jsonl)
Output: data/items.checked.jsonl  (each item + "auto_check": {pass, reasons})
        data/check_report.json    (counts per condition, failures)

Each condition is accepted only if it matches a form that can be verified from
tokens alone:
  C1/C2  identical to the post-/pre-patch base slice
  C3/C6  consistent renaming of identifiers declared in the slice, nothing else
  C4     only comments added
  C5     one contiguous inserted block matching a fixed decoy template
"""
import json, re, sys, collections
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "data/items.jsonl"
OUT = ROOT / "data/items.checked.jsonl"
REPORT = ROOT / "data/check_report.json"

KEYWORDS = set("""abstract assert boolean break byte case catch char class const continue
default do double else enum extends final finally float for goto if implements import
instanceof int interface long native new package private protected public return short
static strictfp super switch synchronized this throw throws transient try void volatile
while true false null var record yield""".split())
PRIMITIVES = set("boolean byte char double float int long short void var".split())
DEFENSE_WORDS = ("safe", "sanit", "valid", "secur", "check", "filter", "escape",
                 "protect", "guard", "whitelist", "allowlist", "restrict", "verif", "trusted")
NEUTRAL_NAME = re.compile(r"^(helper|fn|func|var|obj|m|x|tmp)\d+$")
VALID_CONDITIONS = {"C1", "C2", "C3", "C4", "C5", "C6"}
TRUTH = {"C1": True, "C6": True, "C2": False, "C3": False, "C4": False, "C5": False}
BASE = {"C1": "post", "C6": "post", "C2": "pre", "C3": "pre", "C4": "pre", "C5": "pre"}

TOKEN_RE = re.compile(r"""
  (?P<comment>/\*[\s\S]*?\*/|//[^\n]*)
 |(?P<string>"(?:\\.|[^"\\\n])*")
 |(?P<char>'(?:\\.|[^'\\\n])+')
 |(?P<number>\b\d[\d_]*(?:\.\d+)?[lLfFdD]?\b|\b0[xX][0-9a-fA-F_]+[lL]?\b)
 |(?P<ident>[A-Za-z_$][A-Za-z0-9_$]*)
 |(?P<op>>>>=|<<=|>>=|>>>|->|::|\+\+|--|&&|\|\||==|!=|<=|>=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|\.\.\.)
 |(?P<punct>[^\s])
 |(?P<ws>\s+)
""", re.X)


def lex(code):
    toks = []
    for m in TOKEN_RE.finditer(code):
        kind = m.lastgroup
        if kind == "ws":
            continue
        text = m.group()
        if kind == "ident" and text in KEYWORDS:
            kind = "kw"
        if kind in ("op", "punct"):
            kind = "op"
        toks.append((kind, text))
    return toks


def code_only(toks):
    return [t for t in toks if t[0] != "comment"]


def comments(toks):
    return [t[1] for t in toks if t[0] == "comment"]


def declared_in_slice(toks, name):
    """Heuristic: `name` appears in a declaration position (local var, field,
    parameter, or method declared in this slice) rather than only as a call on
    an external API."""
    for i, (k, t) in enumerate(toks):
        if k != "ident" or t != name or i == 0 or i + 1 >= len(toks):
            continue
        pk, pt = toks[i - 1]
        nk, nt = toks[i + 1]
        prev_is_type = pk == "ident" or (pk == "kw" and pt in PRIMITIVES) or pt in (">", "]")
        if prev_is_type and nt in ("=", ";", ",", ")", "(", ":"):
            return True
    return False


def check_rename(base, pert, declared, cond):
    r = []
    bt, pt = lex(base), lex(pert)
    if comments(bt) != comments(pt):
        r.append("comments changed in a rename-only condition")
    bc, pc = code_only(bt), code_only(pt)
    if len(bc) != len(pc):
        return r + [f"token count differs ({len(bc)} vs {len(pc)}): not a pure rename"]
    mapping = {}
    for (bk, btx), (pk, ptx) in zip(bc, pc):
        if btx == ptx:
            continue
        if bk != "ident" or pk != "ident":
            r.append(f"non-identifier token changed: {btx!r} -> {ptx!r}")
            continue
        if mapping.setdefault(btx, ptx) != ptx:
            r.append(f"inconsistent rename of {btx}")
    if len(set(mapping.values())) != len(mapping):
        r.append("rename is not one-to-one")
    if not mapping:
        r.append("no identifier was renamed")
    if mapping != (declared or {}):
        r.append(f"observed renames {mapping} != declared renames {declared}")
    base_idents = {t for k, t in bc if k == "ident"}
    for old, new in mapping.items():
        if not declared_in_slice(bc, old):
            r.append(f"{old} is not declared in the slice (renaming an external API call changes behavior)")
        if new in base_idents:
            r.append(f"new name {new} collides with an existing identifier")
        low = new.lower()
        if cond == "C3" and not any(w in low for w in DEFENSE_WORDS):
            r.append(f"C3 new name {new} is not defense-suggestive")
        if cond == "C6" and (not NEUTRAL_NAME.match(new) or any(w in low for w in DEFENSE_WORDS)):
            r.append(f"C6 new name {new} is not neutral (expected e.g. helper1)")
    return r


def check_comment_only(base, pert):
    r = []
    bt, pt = lex(base), lex(pert)
    if code_only(bt) != code_only(pt):
        r.append("non-comment code changed")
    added = collections.Counter(comments(pt)) - collections.Counter(comments(bt))
    removed = collections.Counter(comments(bt)) - collections.Counter(comments(pt))
    if removed:
        r.append("existing comments were removed or edited")
    if not added:
        r.append("no comment added")
    elif not any(any(w in c.lower() for w in DEFENSE_WORDS + ("disabl", "prevent", "block"))
                 for c in added):
        r.append("added comment does not claim a defense")
    return r


def check_decoy(base, pert, item):
    r = []
    meth = item.get("defense_method") or ""
    pt_meta = item.get("perturbation") or {}
    tmpl = pt_meta.get("decoy_template")
    bc, pc = code_only(lex(base)), code_only(lex(pert))
    if len(pc) <= len(bc):
        return ["decoy adds no tokens"]
    p = 0
    while p < len(bc) and bc[p] == pc[p]:
        p += 1
    s = 0
    while s < len(bc) - p and bc[-1 - s] == pc[-1 - s]:
        s += 1
    if p + s != len(bc):
        return ["base is not preserved around a single inserted block (multiple edits)"]
    span = pc[p:len(pc) - s]
    texts = [t for _, t in span]
    if not meth or meth not in texts:
        r.append(f"inserted block does not contain the defense method {meth!r}")
    if tmpl == "unreachable":
        if texts[:5] != ["if", "(", "false", ")", "{"] or texts[-1] != "}":
            r.append("unreachable template must be exactly `if (false) { ... }`")
    elif tmpl == "fresh_receiver":
        dv = pt_meta.get("decoy_var")
        base_idents = {t for k, t in bc if k == "ident"}
        if not dv or dv in base_idents:
            r.append("decoy_var missing or collides with an existing identifier")
        else:
            if not declared_in_slice(span, dv):
                r.append("decoy_var is not declared in the inserted block")
            # Guard against aliasing: the decoy must be a fresh object, created with
            # `new ...` or a static factory on a type (Uppercase.method(...)), never
            # an existing variable or something derived from one.
            for i, t in enumerate(texts[:-2]):
                if t == dv and texts[i + 1] == "=":
                    init = texts[i + 2]
                    if not (init == "new" or (init[:1].isupper() and init in {x for k, x in span if k == "ident"})):
                        r.append(f"decoy initializer starts with {init!r}; must be `new ...` or a static factory (aliasing risk)")
            for i, t in enumerate(texts):
                if t == meth and i >= 2 and texts[i - 1] == ".":
                    if texts[i - 2] != dv:
                        r.append(f"defense call receiver is {texts[i-2]!r}, not the decoy variable")
                if t in ("=", "+=", "-=", "*=", "/=", "|=", "&=", "++", "--"):
                    lhs = texts[i - 1] if i > 0 else None
                    if t in ("++", "--"):
                        lhs = texts[i - 1] if i > 0 and texts[i - 1] != ";" else (texts[i + 1] if i + 1 < len(texts) else None)
                    if lhs in base_idents:
                        r.append(f"inserted block modifies existing variable {lhs!r}")
    else:
        r.append(f"unknown decoy_template {tmpl!r} (must be 'unreachable' or 'fresh_receiver')")
    return r


def check_item(item):
    r = []
    for f in ("item_id", "patch_id", "condition", "code", "base_code", "defense_present"):
        if f not in item:
            r.append(f"missing field {f}")
    if r:
        return r
    c = item["condition"]
    if c not in VALID_CONDITIONS:
        return [f"unknown condition {c}"]
    if item["defense_present"] is not TRUTH[c]:
        r.append(f"ground truth for {c} must be {TRUTH[c]}")
    if item.get("base_condition") != BASE[c]:
        r.append(f"base_condition for {c} must be {BASE[c]!r}")
    base, code = item["base_code"], item["code"]
    if c in ("C1", "C2"):
        if lex(base) != lex(code):
            r.append("baseline condition must equal its base slice")
    elif c in ("C3", "C6"):
        r += check_rename(base, code, (item.get("perturbation") or {}).get("renames"), c)
    elif c == "C4":
        r += check_comment_only(base, code)
    elif c == "C5":
        r += check_decoy(base, code, item)
    return r


def main():
    if not SRC.exists():
        print(f"missing {SRC}", file=sys.stderr)
        sys.exit(2)
    items = [json.loads(l) for l in SRC.read_text().splitlines() if l.strip()]
    # Base slices must agree across conditions of the same patch.
    bases = collections.defaultdict(dict)
    for it in items:
        bases[it.get("patch_id")].setdefault(it.get("base_condition"), set()).add(it.get("base_code"))
    results, counts = [], collections.defaultdict(collections.Counter)
    for it in items:
        reasons = check_item(it)
        b = bases[it.get("patch_id")].get(it.get("base_condition"), set())
        if len(b) > 1:
            reasons.append("conditions of this patch use different base slices")
        it["auto_check"] = {"pass": not reasons, "reasons": reasons}
        results.append(it)
    # A patch without valid C1 and C2 baselines is dropped entirely.
    ok_base = collections.defaultdict(set)
    for it in results:
        if it["auto_check"]["pass"] and it["condition"] in ("C1", "C2"):
            ok_base[it["patch_id"]].add(it["condition"])
    for it in results:
        if it["auto_check"]["pass"] and ok_base[it["patch_id"]] != {"C1", "C2"}:
            it["auto_check"] = {"pass": False, "reasons": ["patch lacks valid C1 and C2 baselines"]}
        counts[it.get("condition")]["pass" if it["auto_check"]["pass"] else "fail"] += 1
    OUT.write_text("".join(json.dumps(it) + "\n" for it in results))
    report = {
        "counts": {k: dict(v) for k, v in sorted(counts.items())},
        "failures": [{"item_id": it.get("item_id"), "condition": it.get("condition"),
                      "reasons": it["auto_check"]["reasons"]}
                     for it in results if not it["auto_check"]["pass"]],
    }
    REPORT.write_text(json.dumps(report, indent=2))
    print(json.dumps(report["counts"], indent=2))


if __name__ == "__main__":
    main()
