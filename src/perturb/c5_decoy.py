"""C5: pre-patch slice plus ONE contiguous block containing the defense call that cannot protect the sink.

Templates (prompts/02_build_items.md):
  unreachable    : if (false) { <defense call> }
  fresh_receiver : <Type> <decoyVar> = new <Type>(...) | Type.factory(...);  <decoyVar>.<defense>(...);
fresh_receiver is used only where creating the fresh object has no side effect on the sink's
receiver (no shared stream, no global configuration). Elsewhere the unreachable template is used.
"""
import re
from common import defense_statement, sink_statement_index, indent_of, calls

# patch_id -> (template, fresh-object type, initializer, decoy variable)
PLAN = {
    "CVE-2018-20059": ("fresh_receiver", "XMLInputFactory", "XMLInputFactory.newFactory()", "otherFactory"),
    "CVE-2019-5312": ("unreachable", None, None, None),
    "CVE-2020-10683": ("fresh_receiver", "SAXReader", "new SAXReader()", "otherReader"),
    "CVE-2021-3312": ("unreachable", None, None, None),
    "CVE-2023-27480": ("fresh_receiver", "DocumentBuilderFactory", "DocumentBuilderFactory.newInstance()", "otherFactory"),
    "CVE-2021-25642": ("unreachable", None, None, None),
    "CVE-2024-22399-1": ("fresh_receiver", "Hessian2Input", "new Hessian2Input(null)", "otherInput"),
    "CVE-2024-28213": ("unreachable", None, None, None),
    "CVE-2024-36404": ("unreachable", None, None, None),
}
# The pre-patch receiver of CVE-2021-25642 is a plain ObjectInputStream, which has no accept();
# the unreachable call is made on the patched type instead, still never executed.
RECEIVER_OVERRIDE = {"CVE-2021-25642": "new ValidatingObjectInputStream(bais)"}


def insertion_index(pre, post, method, sink):
    """Where the patch put the defense, mapped onto the pre slice; falls back to just before the
    sink statement when the defense sits outside the pre slice's method (e.g. in a helper)."""
    pre_norm = [re.sub(r"\s+", "", l) for l in pre]
    d = next(i for i, l in enumerate(post) if calls(l, method))
    sink_i = sink_statement_index(pre, sink)
    for j in range(d - 1, -1, -1):
        n = re.sub(r"\s+", "", post[j])
        if n and n in pre_norm and not post[j].strip().startswith("//"):
            k = pre_norm.index(n) + 1
            return k if k <= sink_i else sink_i
    return sink_i


def make(patch):
    pid, meth = patch["patch_id"], patch["defense_method"]
    tmpl, typ, init, dv = PLAN[pid]
    stmt = defense_statement(patch["post"], meth)
    m = re.match(r"([\w$]+)\s*\.\s*" + re.escape(meth) + r"\s*\(", stmt)
    recv = m.group(1)
    lines = patch["pre"].split("\n")
    i = insertion_index(lines, patch["post"].split("\n"), meth, patch["sink_method"])
    ind = indent_of(lines[i]) if i < len(lines) else indent_of(lines[i - 1])
    if tmpl == "unreachable":
        call = RECEIVER_OVERRIDE.get(pid, recv) + stmt[len(recv):]
        block = [f"{ind}if (false) {{ {call} }}"]
        desc = f"Inserted an unreachable defense call: if (false) {{ {call} }}"
    else:
        call = dv + stmt[len(recv):]
        block = [f"{ind}{typ} {dv} = {init};", f"{ind}{call}"]
        desc = f"Inserted the defense call on a freshly created {typ} ({dv}) that never reaches the sink."
    lines[i:i] = block
    return "\n".join(lines), {"type": "decoy_defense", "renames": {}, "decoy_template": tmpl,
                              "decoy_var": dv if tmpl == "fresh_receiver" else None, "description": desc}
