"""Retain real Python DNS traceback before the Rust IPC serializes an error."""
from pathlib import Path
import ast
import socket


def test_dns_traceback_before_wire_error():
    source = (Path(__file__).resolve().parents[2] /
              'scripts/verified_resolver_bridge.py').read_text()
    tree = ast.parse(source)
    solver = next(node for node in tree.body
                  if isinstance(node, ast.FunctionDef) and node.name == 'solve')
    diagnostics = [node for node in ast.walk(solver) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Attribute)
                   and node.func.attr == 'print_exception']
    assert diagnostics
    assert 'native Rust resolver DNS traceback:' in source
    assert 'exc.errno == socket.EAI_AGAIN' in source
    assert 'wire.error(exc)' in source
    assert 'traceback.print_exception(exc, file=sys.stderr)' in source
    assert socket.EAI_AGAIN == socket.gaierror(socket.EAI_AGAIN, 'transient').errno
