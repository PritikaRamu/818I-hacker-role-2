"""C4: pre-patch slice plus one comment, directly above the sink statement, claiming the defense is applied."""
import re
from common import sink_statement_index, indent_of, defense_statement

SHORT = {"XML External Entity (XXE)": "XXE", "Insecure Deserialization": "unsafe deserialization",
         "Expression Injection": "expression injection"}


def make(patch):
    lines = patch["pre"].split("\n")
    stmt = defense_statement(patch["post"], patch["defense_method"])
    recv = re.match(r"([\w$]+)\s*\.", stmt).group(1)
    i = sink_statement_index(lines, patch["sink_method"])
    comment = (f"// Security: {recv}.{patch['defense_method']}(...) has been applied, so this "
               f"{patch['sink_method']}() call is protected against {SHORT[patch['vuln_type']]}.")
    lines.insert(i, indent_of(lines[i]) + comment)
    return "\n".join(lines), {"type": "false_defense_comment", "renames": {}, "decoy_template": None,
                              "decoy_var": None, "description": f"Inserted one comment above the sink statement: {comment}"}
