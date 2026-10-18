#!/usr/bin/env python3
"""Pilot inference: every item x {PRIMARY, NEUTRAL} prompt x {1 sample @ T=0, 5 samples @ T=0.7 seeds 0-4}.

  python3 src/run_pilot.py --base-url URL --model NAME [--limit N] [--mock]
                            [--out results/judgments.jsonl] [--items data/items.final.jsonl]

PRIMARY = VulGenie's defense-identification prompt (paper Fig. 6), prompts/protect_rule.txt,
filled exactly as the release does (f-string substitution of {patch_context}).
NEUTRAL = fixed wording from the pre-registration (REPORT.md §3).
Parsing rules: see parse_primary / parse_neutral and REPORT.md §3.3.
"""
import argparse, asyncio, hashlib, json, os, random, re, sys, time
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRIMARY_FILE = ROOT / "prompts/protect_rule.txt"
LOG_DIR = ROOT / "logs"

NEUTRAL_TEMPLATE = """You are reviewing Java code for security.
Security-sensitive call: {sink_method}
Vulnerability type: {vuln_type}
Code:
{code}
Question: In this code, is the security-sensitive call protected by a defense
that actually prevents the {vuln_type} vulnerability on the value reaching it?
Answer with exactly one word on the first line, DEFENDED or VULNERABLE, then
one sentence of justification."""

SAMPLES = [(0.0, None)] + [(0.7, s) for s in range(5)]
MAX_TOKENS = 1024
CONCURRENCY = 16
MAX_RETRIES = 6


# ---------------------------------------------------------------- prompts
def load_primary_template():
    # Drop the two provenance header lines written by the prompt-extraction script.
    lines = PRIMARY_FILE.read_text(encoding="utf8").split("\n")
    while lines and lines[0].startswith("# "):
        lines.pop(0)
    return "\n".join(lines).rstrip("\n")


def fill_primary(template, item):
    # The release builds this prompt with an f-string whose only field is {patch_context}.
    return template.replace("{patch_context}", item["code"])


def fill_neutral(item):
    return NEUTRAL_TEMPLATE.format(sink_method=item["sink_method"], vuln_type=item["vuln_type"], code=item["code"])


# ---------------------------------------------------------------- sink data flow (for rule 2)
KW = set("""abstract assert boolean break byte case catch char class const continue default do double else
enum extends final finally float for goto if implements import instanceof int interface long native new
package private protected public return short static strictfp super switch synchronized this throw throws
transient try void volatile while true false null var record yield""".split())
TOK = re.compile(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])+\'|[A-Za-z_$][\w$]*|\S')


def _toks(code):
    return [t for t in TOK.findall(code) if not t.startswith(("//", "/*"))]


def _statements(toks):
    out, cur = [], []
    for t in toks:
        if t in (";", "{", "}"):
            if cur:
                out.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        out.append(cur)
    return out


def _idents(stmt):
    """Lower-case identifiers that are not keywords and not method names (not followed by `(`)."""
    nxt = stmt[1:] + [""]
    return {t for t, n in zip(stmt, nxt) if re.fullmatch(r"[a-z_$][\w$]*", t) and t not in KW and n != "("}


def sink_flow_vars(code, sink):
    """Variables whose value reaches the sink call: identifiers in the sink statement(s), closed
    backwards over `x = expr` / `T x = expr` statements, and over `return expr` of helper methods
    declared in the slice that are called from a statement already in the flow."""
    toks = _toks(code)
    stmts = _statements(toks)
    flow = set()
    rel = [s for s in stmts if any(a == sink and b == "(" for a, b in zip(s, s[1:]))]
    for s in rel:
        flow |= _idents(s)
    # helper method declarations: "<type> name (" ... their return statements until the next declaration
    helpers = {}
    cur = None
    for s in stmts:
        for i in range(1, len(s) - 1):
            if s[i + 1] == "(" and re.fullmatch(r"[A-Za-z_$][\w$]*", s[i]) and s[i] not in KW \
                    and (re.fullmatch(r"[\w$>\]]+", s[i - 1]) and s[i - 1] not in KW | {"new", "return"} or s[i - 1] in (">", "]")) \
                    and s[0] in ("public", "private", "protected", "static", "@", "final") :
                cur = s[i]
                helpers.setdefault(cur, set())
                break
        if cur and s and s[0] == "return":
            helpers[cur] |= _idents(s[1:])
    changed, rel_stmts = True, list(rel)
    while changed:
        changed = False
        for s in stmts:
            if "=" in s:
                k = s.index("=")
                lhs = [t for t in s[:k] if re.fullmatch(r"[a-z_$][\w$]*", t) and t not in KW]
                if lhs and lhs[-1] in flow and k + 1 < len(s) and s[k + 1] != "=":
                    new = _idents(s[k + 1:]) - flow
                    if new:
                        flow |= new
                        rel_stmts.append(s)
                        changed = True
        for s in list(rel_stmts):
            for h, ret in helpers.items():
                if h in s and not ret <= flow:
                    flow |= ret
                    changed = True
    return flow


def receivers_of(code, method):
    """Root identifiers of receivers on which `method` is invoked in the code (x.method(...))."""
    out = set()
    toks = _toks(code)
    for i in range(2, len(toks) - 1):
        if toks[i] == method and toks[i + 1] == "(" and toks[i - 1] == ".":
            out.add(toks[i - 2])
    return out


# ---------------------------------------------------------------- parsing
FREE_TEXT_TAGS = ("Value", "SecurityImpact", "Type", "Name", "BelongMethodName", "RelatedMethodName")


def _release_xml(text):
    """VulGenie's own extraction (release utils/util.py::save_xml_file)."""
    if text.find("```xml") != -1 and text.rfind("```") != -1:
        text = text[text.find("```xml"):text.rfind("```") + len("```")]
    return ET.fromstring(text.replace("```xml", "").replace("```", ""))


def _escaped_xml(text):
    """Same extraction, but XML-escape the contents of free-text elements first (code snippets with
    `<`, `&&` or generics make the release parser fail on otherwise well-formed answers)."""
    if text.find("```xml") != -1 and text.rfind("```") != -1:
        text = text[text.find("```xml"):text.rfind("```") + len("```")]
    text = text.replace("```xml", "").replace("```", "")

    def esc(m):
        body = m.group(2).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f"<{m.group(1)}>{body}</{m.group(1)}>"
    text = re.sub(r"<(%s)>([\s\S]*?)</\1>" % "|".join(FREE_TEXT_TAGS), esc, text)
    start = text.find("<DefenseRule")
    end = text.rfind("</DefenseRule>")
    if start == -1 or end == -1:
        raise ValueError("no <DefenseRule> element")
    return ET.fromstring(text[start:end + len("</DefenseRule>")])


def parse_primary(text, item):
    """the pre-registration rule 2. defended  <=> some <Variable> has numeric Level >= 5 and acts on the object or
    argument reaching the sink: its Name's root identifier is in the sink's data flow, or the method it
    names (RelatedMethodName, or Name itself) is invoked in the code on a receiver in that flow.
    not_defended <=> parsed, and no variable qualifies. parse_fail <=> no parseable DefenseRule XML, or
    variables are present but none has a numeric Level."""
    if not text:
        return "parse_fail", {"why": "empty output"}
    root, mode = None, None
    for mode, fn in (("release", _release_xml), ("escaped", _escaped_xml)):
        try:
            root = fn(text)
            break
        except Exception:
            root = None
    if root is None:
        return "parse_fail", {"why": "xml not parseable"}
    if root.tag != "DefenseRule" and root.find(".//DefenseMechanism") is None and root.find(".//Variable") is None:
        return "parse_fail", {"why": f"unexpected root <{root.tag}>", "mode": mode}
    variables = root.findall(".//Variable")
    flow = sink_flow_vars(item["code"], item["sink_method"])
    numeric, hits = 0, []
    for v in variables:
        get = lambda tag: (v.find(tag).text or "").strip() if v.find(tag) is not None and v.find(tag).text else ""
        try:
            level = float(re.match(r"\s*(\d+(?:\.\d+)?)", get("Level")).group(1))
        except Exception:
            continue
        numeric += 1
        if level < 5:
            continue
        name, rel = get("Name"), get("RelatedMethodName")
        name_root = None
        m = re.match(r"(?:this\s*\.\s*)?([A-Za-z_$][\w$]*)", name)
        if m:
            name_root = m.group(1)
        methods = {x for x in (re.sub(r"\(.*$", "", rel).split(".")[-1].strip(),) if x and x.lower() != "none"}
        if name_root:
            methods.add(name_root)
            tail = re.findall(r"\.\s*([A-Za-z_$][\w$]*)\s*\(", name)
            methods |= set(tail)
        acts = (name_root in flow) or any(receivers_of(item["code"], mth) & flow for mth in methods)
        if acts:
            hits.append({"name": name, "related": rel, "level": level})
    detail = {"mode": mode, "n_variables": len(variables), "qualifying": hits, "sink_flow": sorted(flow)}
    if variables and numeric == 0:
        return "parse_fail", dict(detail, why="no numeric Level")
    return ("defended" if hits else "not_defended"), detail


def parse_neutral(text):
    """First non-empty line must be the single word DEFENDED or VULNERABLE (markdown emphasis and
    trailing punctuation tolerated, case-insensitive). Anything else is parse_fail."""
    if not text:
        return "parse_fail", {"why": "empty output"}
    first = next((l for l in text.strip().split("\n") if l.strip()), "")
    word = re.sub(r"^[\s*_`#>]+|[\s*_`.:!,]+$", "", first).upper()
    if word == "DEFENDED":
        return "defended", {}
    if word == "VULNERABLE":
        return "not_defended", {}
    return "parse_fail", {"why": f"first line not a verdict: {first[:80]!r}"}


# ---------------------------------------------------------------- mock
def mock_output(item, prompt_name, temperature, seed):
    """Deterministic canned outputs: ~45% defended, ~40% not defended, ~15% unparseable."""
    h = int(hashlib.sha256(f"{item['item_id']}|{prompt_name}|{temperature}|{seed}".encode()).hexdigest(), 16) % 100
    kind = "def" if h < 45 else ("not" if h < 85 else "bad")
    if prompt_name == "NEUTRAL":
        return {"def": "DEFENDED\nThe receiver is configured before the call.",
                "not": "**VULNERABLE**\nNothing restricts the input reaching the call.",
                "bad": "It depends on how the factory is configured elsewhere."}[kind]
    if kind == "bad":
        return "<DefenseRule><DefenseMechanism><Variables><Variable><Name>x</Name>"  # truncated XML
    flow = sorted(sink_flow_vars(item["code"], item["sink_method"])) or ["unknown"]
    name = flow[0] if kind == "def" else "unrelatedVariable"
    level = 8 if kind == "def" else 3
    return (f"```xml\n<DefenseRule language=\"java\">\n  <DefenseMechanism>\n    <CodeSnippet><Value>if (a < b && c)</Value></CodeSnippet>\n"
            f"    <Variables><Variable><isLocal>true</isLocal><Name>{name}</Name><BelongMethodName>m</BelongMethodName>"
            f"<RelatedMethodName>None</RelatedMethodName><Level>{level}</Level><Type>(3) object property settings</Type></Variable></Variables>\n"
            f"    <SecurityImpact>mock</SecurityImpact>\n  </DefenseMechanism>\n</DefenseRule>\n```")


# ---------------------------------------------------------------- run
async def call_llm(client, sem, model, prompt, temperature, seed):
    kwargs = dict(model=model, messages=[{"role": "user", "content": prompt}], temperature=temperature,
                  max_tokens=MAX_TOKENS)
    if seed is not None:
        kwargs["seed"] = seed
    delay = 2.0
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with sem:
                resp = await client.chat.completions.create(**kwargs)
            return resp.choices[0].message.content or "", resp.choices[0].finish_reason
        except Exception as e:  # network / server errors: back off and retry, then fail loudly
            if attempt == MAX_RETRIES:
                raise RuntimeError(f"LLM call failed after {MAX_RETRIES} attempts: {e!r}")
            await asyncio.sleep(delay + random.random())
            delay *= 2


async def run(args, items):
    template = load_primary_template()
    (LOG_DIR / "prompts").mkdir(parents=True, exist_ok=True)
    jobs = []
    for it in items:
        prompts = {"PRIMARY": fill_primary(template, it), "NEUTRAL": fill_neutral(it)}
        for pname, prompt in prompts.items():
            (LOG_DIR / "prompts" / f"{it['item_id']}__{pname}.txt").write_text(prompt, encoding="utf8")
            for temperature, seed in SAMPLES:
                jobs.append((it, pname, prompt, temperature, seed))

    client = sem = None
    if not args.mock:
        from openai import AsyncOpenAI  # imported lazily so --mock needs no extra packages
        client = AsyncOpenAI(base_url=args.base_url, api_key=os.environ.get("OPENAI_API_KEY", "EMPTY"), timeout=600)
        sem = asyncio.Semaphore(CONCURRENCY)

    async def one(job):
        it, pname, prompt, temperature, seed = job
        if args.mock:
            raw, finish = mock_output(it, pname, temperature, seed), "mock"
        else:
            raw, finish = await call_llm(client, sem, args.model, prompt, temperature, seed)
        judgment, detail = parse_primary(raw, it) if pname == "PRIMARY" else parse_neutral(raw)
        return {"item_id": it["item_id"], "patch_id": it["patch_id"], "condition": it["condition"],
                "prompt_name": pname, "temperature": temperature, "seed": seed, "raw_output": raw,
                "judgment": judgment, "ground_truth": "defended" if it["defense_present"] else "not_defended",
                "finish_reason": finish, "parse_detail": detail}

    t0 = time.time()
    rows = await asyncio.gather(*(one(j) for j in jobs))
    return rows, time.time() - t0


def wandb_log(args, items, rows, seconds):
    if args.mock and "WANDB_MODE" not in os.environ:
        os.environ["WANDB_MODE"] = "disabled"  # mock tests must not touch the network
    try:
        import wandb
    except ImportError:
        print("[run_pilot] wandb not installed; skipping W&B logging", file=sys.stderr)
        return
    cfg = {"model": args.model, "base_url": args.base_url, "mock": args.mock, "n_items": len(items),
           "samples": [{"temperature": t, "seed": s} for t, s in SAMPLES], "max_tokens": MAX_TOKENS,
           "concurrency": CONCURRENCY, "primary_prompt": str(PRIMARY_FILE.relative_to(ROOT)), "out": args.out}
    run = wandb.init(project="vulgenie-cue-study", config=cfg, job_type="mock" if args.mock else "pilot")
    table = wandb.Table(columns=["prompt", "condition", "temperature", "defended", "not_defended", "parse_fail"])
    counts = Counter((r["prompt_name"], r["condition"], r["temperature"], r["judgment"]) for r in rows)
    for p in ("PRIMARY", "NEUTRAL"):
        for c in sorted({r["condition"] for r in rows}):
            for t in (0.0, 0.7):
                table.add_data(p, c, t, *(counts[(p, c, t, j)] for j in ("defended", "not_defended", "parse_fail")))
    wandb.log({"counts": table, "n_calls": len(rows), "seconds": seconds})
    run.finish()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8011/v1")
    ap.add_argument("--model", default="qwen-coder-32b")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "results/judgments.jsonl"))
    ap.add_argument("--items", default=str(ROOT / "data/items.final.jsonl"))
    args = ap.parse_args()

    items = [json.loads(l) for l in Path(args.items).read_text().splitlines() if l.strip()]
    if args.limit:
        items = items[: args.limit]
    if not items:
        sys.exit(f"no items in {args.items}")
    rows, seconds = asyncio.run(run(args, items))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(r) + "\n" for r in rows))
    counts = Counter((r["prompt_name"], r["condition"], r["judgment"]) for r in rows)
    print(f"[run_pilot] {len(rows)} calls for {len(items)} items in {seconds:.1f}s -> {out}")
    for p in ("PRIMARY", "NEUTRAL"):
        for c in sorted({r["condition"] for r in rows}):
            print(f"  {p:8} {c}: " + "  ".join(f"{j}={counts[(p, c, j)]}" for j in ("defended", "not_defended", "parse_fail")))
    wandb_log(args, items, rows, seconds)


if __name__ == "__main__":
    main()
