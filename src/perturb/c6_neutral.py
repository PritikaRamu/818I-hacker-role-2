"""C6: post-patch slice, identifiers declared in the slice renamed to neutral names (var1, helper1)."""
from common import declared_names, declared_helper_methods, apply_renames, identifiers


def make(patch):
    base = patch["post"]
    taken = set(identifiers(base))
    mapping, nv, nh = {}, 0, 0
    for old in declared_names(base):
        nv += 1
        while f"var{nv}" in taken:
            nv += 1
        mapping[old] = f"var{nv}"
    for old in declared_helper_methods(base):
        nh += 1
        while f"helper{nh}" in taken:
            nh += 1
        mapping[old] = f"helper{nh}"
    code = apply_renames(base, mapping)
    return code, {"type": "rename_neutral", "renames": mapping, "decoy_template": None, "decoy_var": None,
                  "description": f"Renamed {len(mapping)} identifiers declared in the post-patch slice to neutral "
                                 f"names; library API calls (including the defense call) keep their names."}
