"""Load the pinned upstream functions without its Docker/dataset CLI imports.

All six upstream files are stored byte-for-byte. Only absolute package imports
are redirected into a private namespace. The five utility functions below are
compiled from their original AST, retaining the official path-selection logic.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import re
import sys
import types
import uuid
from functools import cache
from pathlib import Path

ROOT = Path(__file__).parent
PINS = json.loads((ROOT / "pins.json").read_text())


def load(get):
    package = "_gpt_trace_swegym_" + uuid.uuid4().hex
    namespace = types.ModuleType(package)
    namespace.__path__ = [str(ROOT / "upstream")]
    sys.modules[package] = namespace
    for name, digest in PINS["upstream_files"].items():
        raw = (ROOT / "upstream" / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError(f"pinned SWE-Gym harness module changed: {name}")
    def module(name):
        path = ROOT / "upstream" / (name + ".py")
        obj = types.ModuleType(package + "." + name)
        obj.__file__ = str(path)
        obj.__package__ = package
        sys.modules[obj.__name__] = obj
        raw = path.read_text().replace("swegym.harness.", package + ".")
        exec(compile(raw, str(path), "exec"), obj.__dict__)
        return obj
    constants = module("constants")
    utils = types.ModuleType(package + ".utils")
    sys.modules[utils.__name__] = utils
    utils.__dict__.update(vars(constants))
    utils.__dict__.update(os=os, re=re, cache=cache, requests=types.SimpleNamespace(get=get))
    tree = ast.parse((ROOT / "upstream/utils.py").read_text())
    names = {"get_environment_yml_by_commit", "get_environment_yml",
             "get_requirements_by_commit", "get_requirements", "get_test_directives"}
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in selected} != names:
        raise RuntimeError("pinned SWE-Gym utility contract changed")
    exec(compile(ast.Module(body=selected, type_ignores=[]), "pinned-swegym-utils", "exec"), utils.__dict__)
    module("dockerfiles")
    test_spec = module("test_spec")
    parsers = module("log_parsers")
    grading = module("grading")
    return types.SimpleNamespace(constants=constants, utils=utils, test_spec=test_spec,
                                 parsers=parsers, grading=grading)
