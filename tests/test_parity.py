import json
import subprocess
import shutil
import pytest

from algorithms.rsa import codegen as py_cg
from algorithms.rsa import validators as py_v


STATE_FULL = {
    "p": 61, "q": 53, "n": 3233, "phi": 3120, "e": 17, "d": 2753,
    "m": 65, "c": pow(65, 17, 3233), "m_decrypted": 65,
}

CODEGEN_KEYS = ["pick_pq", "compute_n", "compute_phi", "pick_e", "compute_d",
                "pick_message", "encrypt", "decrypt", "info"]

VALIDATOR_CASES = [
    ("pick_pq",      {"p": "61", "q": "53"},                                {}),
    ("pick_pq",      {"p": "60", "q": "53"},                                {}),
    ("compute_n",    "3233",                                                {"p": 61, "q": 53}),
    ("compute_n",    "3000",                                                {"p": 61, "q": 53}),
    ("compute_phi",  "3120",                                                {"p": 61, "q": 53}),
    ("pick_e",       "17",                                                  {"phi": 3120}),
    ("pick_e",       "6",                                                   {"phi": 3120}),
    ("compute_d",    "2753",                                                {"e": 17, "phi": 3120}),
    ("pick_message", "65",                                                  {"n": 3233}),
    ("encrypt",      str(pow(65, 17, 3233)),                                {"m": 65, "e": 17, "n": 3233}),
    ("decrypt",      "65",                                                  {"c": pow(65, 17, 3233), "d": 2753, "n": 3233}),
]


def _node_available():
    return shutil.which("node") is not None


def _run_node(script):
    """Run a node ESM snippet and return its stdout, parsed as JSON."""
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, f"node failed: stderr={proc.stderr}, stdout={proc.stdout}"
    return json.loads(proc.stdout.strip())


@pytest.mark.skipif(not _node_available(), reason="node not in PATH")
def test_codegen_parity():
    state_json = json.dumps(STATE_FULL)
    script = f"""
import * as cg from "./static/algorithms/rsa/codegen.js";
const state = {state_json};
const out = {{}};
for (const k of {json.dumps(CODEGEN_KEYS)}) {{
  out[k] = cg[k](state);
}}
out.__full__ = cg.full_script(state);
process.stdout.write(JSON.stringify(out));
"""
    js_out = _run_node(script)
    for k in CODEGEN_KEYS:
        py = getattr(py_cg, k)(STATE_FULL)
        assert js_out[k] == py, f"codegen[{k}] diverged: JS={js_out[k]!r} PY={py!r}"
    assert js_out["__full__"] == py_cg.full_script(STATE_FULL)


@pytest.mark.skipif(not _node_available(), reason="node not in PATH")
def test_validator_parity():
    cases_json = json.dumps(VALIDATOR_CASES)
    script = f"""
import * as v from "./static/algorithms/rsa/validators.js";
const cases = {cases_json};
const out = [];
for (const [name, input, state] of cases) {{
  out.push(v[name](input, state));
}}
process.stdout.write(JSON.stringify(out));
"""
    js_out = _run_node(script)
    for (name, inp, state), js_result in zip(VALIDATOR_CASES, js_out):
        py_result = getattr(py_v, name)(inp, state)
        assert js_result["ok"] == py_result["ok"], f"{name}: ok diverged"
        if py_result["ok"]:
            assert js_result["value"] == py_result["value"], f"{name}: value diverged"
