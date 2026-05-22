from .algorithm_loader import get_validators, AlgorithmNotFound


_RSA_SEQUENCE = [
    ("pick_pq",      lambda s: {"p": s.get("p"), "q": s.get("q")}, ["p", "q"]),
    ("compute_n",    lambda s: str(s.get("n", "")),                 ["n", "p", "q"]),
    ("compute_phi",  lambda s: str(s.get("phi", "")),               ["phi", "p", "q"]),
    ("pick_e",       lambda s: str(s.get("e", "")),                 ["e", "phi"]),
    ("compute_d",    lambda s: str(s.get("d", "")),                 ["d", "e", "phi"]),
    ("pick_message", lambda s: str(s.get("m", "")),                 ["m", "n"]),
    ("encrypt",      lambda s: str(s.get("c", "")),                 ["c", "m", "e", "n"]),
    ("decrypt",      lambda s: str(s.get("m_decrypted", "")),       ["m_decrypted", "c", "d", "n"]),
]

_SEQUENCES = {"rsa": _RSA_SEQUENCE}


def validate_state(algorithm_slug: str, state: dict) -> tuple[bool, str]:
    """Re-run the algorithm's validator sequence against the claimed state.
    Returns (ok, error_message). Skips validators whose state keys aren't all present.
    """
    try:
        validators = get_validators(algorithm_slug)
    except AlgorithmNotFound as e:
        return False, str(e)
    seq = _SEQUENCES.get(algorithm_slug)
    if not seq:
        return True, ""  # no sequence defined: accept
    for key, input_fn, required in seq:
        if not all(k in state for k in required):
            continue
        result = getattr(validators, key)(input_fn(state), state)
        if not result["ok"]:
            return False, f"step {key}: {result['hint']}"
    return True, ""
