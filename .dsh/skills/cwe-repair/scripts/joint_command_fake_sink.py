#!/usr/bin/env python3
"""Bounded local fake-sink simulation for the JointCmd parallel-array contract.

This deliberately models the required repair policy; it is not a binary built
from AGIBOT/AimRT production sources and must remain reduced-harness evidence.
"""
import json
import sys
from pathlib import Path

FIELDS = ("position", "velocity", "effort", "stiffness", "damping")


def run(fixture):
    command = fixture.get("joint_command", {})
    names = command.get("name")
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        return {"ret": -1, "reason": "invalid-name-vector", "state_mutated": False, "transform_count": 0, "fake_publish_count": 0}
    for field in FIELDS:
        values = command.get(field)
        if not isinstance(values, list) or len(values) != len(names):
            return {"ret": -1, "reason": "parallel-array-length-mismatch:" + field, "state_mutated": False, "transform_count": 0, "fake_publish_count": 0}
    known = set(fixture.get("known_joints", []))
    if not known or any(name not in known for name in names):
        return {"ret": -1, "reason": "unknown-joint", "state_mutated": False, "transform_count": 0, "fake_publish_count": 0}
    return {"ret": 0, "reason": "accepted", "state_mutated": bool(names), "transform_count": 1, "fake_publish_count": len(names)}


def main():
    if len(sys.argv) != 2:
        print("ret=-1 fake_publish_count=0 state_mutated=false reason=usage")
        return 2
    try:
        fixture = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print("ret=-1 fake_publish_count=0 state_mutated=false reason=fixture-invalid")
        return 2
    result = run(fixture)
    print("ret={ret} fake_publish_count={fake_publish_count} state_mutated={state_mutated} transform_count={transform_count} reason={reason}".format(**result))
    return 0 if result["ret"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
