#!/usr/bin/env python3
"""Diff-extraction of pre-/post-patch slices (pre-registration rule 4; method in REPORT.md §4).

Reads the release's own SMBG usage-pair slices directly from release/ASRDataset.zip
(GroundTruth/<CVE>/usage_pairs/<rule>-{diff,unpatched,patched}.java) and writes
data/slices.json with, per patch, the pre-patch and post-patch slice of the client
method(s) that contain the sink call (and, post-patch, the defense call).

  - client portion of <rule>-diff.java: lines after the header comment, up to the first
    top-level declaration that follows a blank line (where the API's library source begins)
  - '+' line -> post only, '-' line -> pre only (marker removed)
  - unmarked line -> both, except: if it is missing from one side's file while that file is a
    "full view" (contains >= 50% of the diff's unmarked lines), it goes only to the other side.
    This resolves modified lines that the release prints twice without markers, while partial
    or empty -unpatched.java files (common in the release) are not trusted
  - the pipeline's injected marker comments ("// Methods Declaration" etc.) go to both sides
Comments and identifiers are kept exactly as in the release slice.
"""
import json, re, sys, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZIP = ROOT / "release/ASRDataset.zip"
OUT = ROOT / "data/slices.json"

# Selection from REPORT.md §5 (all eligible patches; the pre-registration rule 5).
PATCHES = [
    # patch_id, rule file stem, vuln_type, defense_method, sink_method
    ("CVE-2018-20059", "CVE-2018-20059-ContextCheck-ea926906cc0380ca5b4a658d65802b1e", "XML External Entity (XXE)", "setProperty", "unmarshal"),
    ("CVE-2019-5312", "CVE-2019-5312-ContextCheck-6a2750a8ad411aa151b2ee95994d8ae4", "XML External Entity (XXE)", "setFeature", "parse"),
    ("CVE-2020-10683", "CVE-2020-10683-ContextCheck-3f08704edbb1884e61db0c3dd9f5a017", "XML External Entity (XXE)", "setFeature", "read"),
    ("CVE-2021-3312", "CVE-2021-3312-VulnModelAnalysis-788cbe49547b64f32f3b7c1fbd502343", "XML External Entity (XXE)", "setEntityResolver", "read"),
    ("CVE-2023-27480", "CVE-2023-27480-ContextCheck-6a2750a8ad411aa151b2ee95994d8ae4", "XML External Entity (XXE)", "setFeature", "parse"),
    ("CVE-2021-25642", "CVE-2021-25642-ContextCheck-4f642135083b0201ce393b87991307b8", "Insecure Deserialization", "accept", "readObject"),
    ("CVE-2024-22399-1", "CVE-2024-22399-1-ContextCheck-019310968db7d267fc8d6182998ecc75", "Insecure Deserialization", "setSerializerFactory", "readObject"),
    ("CVE-2024-28213", "CVE-2024-28213-ContextCheck-4f642135083b0201ce393b87991307b8", "Insecure Deserialization", "setObjectInputFilter", "readObject"),
    ("CVE-2024-36404", "CVE-2024-36404-BaseAnalysis-05e0004fdee410cc4c134c8de5842240", "Expression Injection", "setFunctions", "getValue"),
]
CVE_OF = {"CVE-2024-22399-1": "CVE-2024-22399"}

LIB_START = re.compile(r"^\s{0,4}(public|protected|private|@Override|/\*\*|[\w.<>\[\]]+\s+\w+\s*\()")
INJECTED = {"// Class Declaration", "// Methods Declaration", "// Field Declaration or Other Static Code Declaration"}


def norm(s):
    return re.sub(r"\s+", "", s)


def client_lines(text):
    lines = text.split("\n")[1:]  # drop "// API Usage in the Diff:" header
    out, blank = [], False
    for l in lines:
        if not l.strip():
            blank = True
            continue
        if blank and out and not l.startswith(("+", "-")) and LIB_START.match(l):
            break
        blank = False
        out.append(l)
    return out


def strip_marker(l):
    # the release writes changed lines as "+ <original line>" / "- <original line>"
    if l[:2] in ("+ ", "- "):
        return l[2:]
    return l[1:] if l[:1] in "+-" else l


def views(diff_lines, unpatched, patched):
    in_pre = {norm(strip_marker(l)) for l in unpatched.split("\n")}
    in_post = {norm(strip_marker(l)) for l in patched.split("\n")}
    unmarked = [norm(l) for l in diff_lines if l[:1] not in "+-" and l.strip()]
    full = lambda side: bool(unmarked) and sum(u in side for u in unmarked) >= 0.5 * len(unmarked)
    pre_full, post_full = full(in_pre), full(in_post)
    pre, post = [], []
    for l in diff_lines:
        if l.startswith("+"):
            post.append(strip_marker(l))
        elif l.startswith("-"):
            pre.append(strip_marker(l))
        else:
            n = norm(l)
            a = b = True
            if l.strip() not in INJECTED:
                if pre_full and n not in in_pre and n in in_post:
                    a = False
                if post_full and n not in in_post and n in in_pre:
                    b = False
            if a:
                pre.append(l)
            if b:
                post.append(l)
    return pre, post


def dedent(lines):
    ind = min((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
    return "\n".join(l[ind:].rstrip() for l in lines) + "\n"


def calls(code, m):
    return len(re.findall(r"(?<![\w$])" + re.escape(m) + r"\s*\(", code))


def main():
    zf = zipfile.ZipFile(ZIP)
    out = []
    for pid, stem, vtype, dmeth, smeth in PATCHES:
        base = f"ASRDataset/GroundTruth/{pid}/usage_pairs/{stem}"
        rd = lambda suf: zf.read(f"{base}-{suf}.java").decode("utf8", "replace")
        pre, post = views(client_lines(rd("diff")), rd("unpatched"), rd("patched"))
        pre_code, post_code = dedent(pre), dedent(post)
        checks = {"defense_in_post": calls(post_code, dmeth) > 0, "defense_absent_pre": calls(pre_code, dmeth) == 0,
                  "sink_in_pre": calls(pre_code, smeth) > 0, "sink_in_post": calls(post_code, smeth) > 0}
        if not all(checks.values()):
            print(f"[extract] {pid}: eligibility check failed {checks}", file=sys.stderr)
            continue
        out.append({"patch_id": pid, "cve": CVE_OF.get(pid, pid), "vuln_type": vtype,
                    "defense_method": dmeth, "sink_method": smeth,
                    "source": f"release/ASRDataset.zip :: {base}-{{diff,unpatched,patched}}.java",
                    "pre": pre_code, "post": post_code})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2))
    print(f"[extract] wrote {len(out)} patches to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
