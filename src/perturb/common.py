"""Shared helpers for the perturbation generators (tokenizer, declaration finder, line utils).

This is generator code. It is intentionally independent of check_items.py.
"""
import re

KEYWORDS = set("""abstract assert boolean break byte case catch char class const continue
default do double else enum extends final finally float for goto if implements import
instanceof int interface long native new package private protected public return short
static strictfp super switch synchronized this throw throws transient try void volatile
while true false null var record yield""".split())
PRIMITIVES = set("boolean byte char double float int long short".split())

TOKEN = re.compile(r"""
  (?P<comment>/\*[\s\S]*?\*/|//[^\n]*)
 |(?P<string>"(?:\\.|[^"\\\n])*")
 |(?P<char>'(?:\\.|[^'\\\n])+')
 |(?P<number>\b\d[\d_]*(?:\.\d+)?[lLfFdD]?\b|\b0[xX][0-9a-fA-F_]+[lL]?\b)
 |(?P<ident>[A-Za-z_$][A-Za-z0-9_$]*)
 |(?P<ws>\s+)
 |(?P<op>->|::|\+\+|--|&&|\|\||==|!=|<=|>=|\+=|-=|\*=|/=|\.\.\.|[^\s])
""", re.X)


def tokens(code):
    """[(kind, text, start, end)] for every token, including whitespace and comments."""
    out = []
    for m in TOKEN.finditer(code):
        k = m.lastgroup
        if k == "ident" and m.group() in KEYWORDS:
            k = "kw"
        out.append((k, m.group(), m.start(), m.end()))
    return out


def code_tokens(code):
    return [t for t in tokens(code) if t[0] not in ("ws", "comment")]


def declared_names(code):
    """Local variables and parameters declared in the slice, in order of first declaration.

    A name counts as declared if it follows a type (identifier, primitive, `>` or `]`) and is
    followed by `=`, `;`, `,`, `)` or `:`. Excluded: names starting with an uppercase letter,
    names ever used after `.` (fields/methods of other objects), and names ever called as `name(`.
    Lambda parameters and fields declared elsewhere are therefore never renamed.
    """
    toks = code_tokens(code)
    after_dot, called, found = set(), set(), []
    for i, (k, t, _, _) in enumerate(toks):
        if k != "ident":
            continue
        if i > 0 and toks[i - 1][1] == ".":
            after_dot.add(t)
        if i + 1 < len(toks) and toks[i + 1][1] == "(":
            called.add(t)
    for i, (k, t, _, _) in enumerate(toks):
        if k != "ident" or i == 0 or i + 1 >= len(toks) or not t[0].islower():
            continue
        pk, pt = toks[i - 1][0], toks[i - 1][1]
        nt = toks[i + 1][1]
        prev_is_type = pk == "ident" or (pk == "kw" and pt in PRIMITIVES) or pt in (">", "]")
        if prev_is_type and nt in ("=", ";", ",", ")", ":") and t not in found:
            found.append(t)
    return [n for n in found if n not in after_dot and n not in called]


def declared_helper_methods(code):
    """Methods declared in the slice that are also called inside it and are not @Override."""
    toks = code_tokens(code)
    out = []
    for i, (k, t, _, _) in enumerate(toks):
        if k != "ident" or i == 0 or i + 1 >= len(toks) or toks[i + 1][1] != "(":
            continue
        pk, pt = toks[i - 1][0], toks[i - 1][1]
        if not (pk == "ident" or (pk == "kw" and pt in PRIMITIVES | {"void"}) or pt in (">", "]")):
            continue
        # look back over modifiers/annotations of this declaration for @Override
        j, override = i - 2, False
        while j >= 0 and toks[j][1] not in (";", "{", "}"):
            if toks[j][1] == "Override" and j > 0 and toks[j - 1][1] == "@":
                override = True
            j -= 1
        n_calls = sum(1 for a, b in zip(toks, toks[1:]) if a[1] == t and b[1] == "(")
        if not override and n_calls >= 2 and t not in out:
            out.append(t)
    return out


def apply_renames(code, mapping):
    """Rename identifier tokens only; comments, strings and whitespace are untouched."""
    parts = []
    for k, t, _, _ in tokens(code):
        parts.append(mapping.get(t, t) if k == "ident" else t)
    return "".join(parts)


def identifiers(code):
    return {t for k, t, _, _ in code_tokens(code) if k in ("ident", "kw")}


def calls(code, method):
    return len(re.findall(r"(?<![\w$])" + re.escape(method) + r"\s*\(", code))


def indent_of(line):
    return line[: len(line) - len(line.lstrip())]


def sink_statement_index(lines, sink):
    """Index of the first line of the statement that contains the first sink call."""
    idx = next(i for i, l in enumerate(lines) if calls(l, sink))
    while idx > 0 and lines[idx - 1].rstrip() and not lines[idx - 1].rstrip().endswith((";", "{", "}")) \
            and not lines[idx - 1].strip().startswith("//"):
        idx -= 1
    return idx


def defense_statement(post_code, method):
    """The first post-patch line that calls the defense method, stripped."""
    return next(l.strip() for l in post_code.split("\n") if calls(l, method))
