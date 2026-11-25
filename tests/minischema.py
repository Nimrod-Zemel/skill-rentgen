"""A small JSON Schema checker with no dependency.

It covers what the schemas in this repository and the vendored
cowork-harness schemas use: type, enum, const, required, properties,
additionalProperties, propertyNames, items, minItems, minLength, pattern,
minimum, maximum, exclusiveMinimum, allOf, anyOf, oneOf, not and
if/then/else. Enough to keep published schemas and real output from
drifting apart.
"""
from __future__ import annotations

import re

TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool,
         "object": dict, "array": list, "null": type(None)}


def check(value, schema, path="$"):
    """Return a list of problems. Empty means the value fits the schema."""
    if schema is True or schema == {}:
        return []
    if schema is False:
        return ["%s: nothing is allowed here" % path]
    problems = []
    kinds = schema.get("type")
    if kinds:
        kinds = kinds if isinstance(kinds, list) else [kinds]
        fits = any(isinstance(value, TYPES[k]) and not (k in ("integer", "number")
                                                        and isinstance(value, bool)) for k in kinds)
        if not fits:
            return ["%s: expected %s" % (path, "/".join(kinds))]
    if "enum" in schema and value not in schema["enum"]:
        problems.append("%s: %r is not one of %r" % (path, value, schema["enum"]))
    if "const" in schema and value != schema["const"]:
        problems.append("%s: must be %r" % (path, schema["const"]))
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            problems.append("%s: too short" % path)
        if "pattern" in schema and not re.search(schema["pattern"], value):
            problems.append("%s: does not match %s" % (path, schema["pattern"]))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            problems.append("%s: below the minimum" % path)
        if "maximum" in schema and value > schema["maximum"]:
            problems.append("%s: above the maximum" % path)
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            problems.append("%s: not above the minimum" % path)
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                problems.append("%s: missing %s" % (path, key))
        known = schema.get("properties", {})
        for key, sub in known.items():
            if key in value:
                problems += check(value[key], sub, path + "." + key)
        extra = schema.get("additionalProperties")
        for key, item in value.items():
            if key in known:
                continue
            if extra is False:
                problems.append("%s: unknown key %s" % (path, key))
            elif isinstance(extra, dict):
                problems += check(item, extra, path + "." + key)
        if isinstance(schema.get("propertyNames"), dict):
            for key in value:
                problems += check(key, schema["propertyNames"], path + "{" + key + "}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            problems.append("%s: too few items" % path)
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(value):
                problems += check(item, schema["items"], "%s[%d]" % (path, index))
    for sub in schema.get("allOf", []):
        problems += check(value, sub, path)
    if "anyOf" in schema and not any(not check(value, sub, path) for sub in schema["anyOf"]):
        problems.append("%s: fits none of the allowed shapes" % path)
    if "oneOf" in schema and sum(1 for sub in schema["oneOf"] if not check(value, sub, path)) != 1:
        problems.append("%s: must fit exactly one of the allowed shapes" % path)
    if "not" in schema and not check(value, schema["not"], path):
        problems.append("%s: fits a shape that is ruled out" % path)
    if "if" in schema:
        branch = "then" if not check(value, schema["if"], path) else "else"
        if branch in schema:
            problems += check(value, schema[branch], path)
    return problems


validate = check
