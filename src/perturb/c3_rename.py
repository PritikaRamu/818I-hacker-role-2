"""C3: pre-patch slice, identifiers declared in the slice renamed to defense-suggestive names."""
from common import declared_names, declared_helper_methods, apply_renames, identifiers

PREFIXES = ("safe", "secure", "validated", "sanitized")


def suggestive(name, taken):
    for p in PREFIXES:
        new = p + name[0].upper() + name[1:]
        if new not in taken:
            return new
    raise ValueError(f"no free defense-suggestive name for {name}")


def make(patch):
    base = patch["pre"]
    taken = set(identifiers(base))
    mapping = {}
    for old in declared_names(base) + declared_helper_methods(base):
        mapping[old] = suggestive(old, taken)
        taken.add(mapping[old])
    code = apply_renames(base, mapping)
    return code, {"type": "rename_defense_suggestive", "renames": mapping, "decoy_template": None,
                  "decoy_var": None,
                  "description": f"Renamed {len(mapping)} identifiers declared in the pre-patch slice "
                                 f"(locals/parameters{', helper methods' if declared_helper_methods(base) else ''}) "
                                 f"to defense-suggestive names; nothing else changed."}
