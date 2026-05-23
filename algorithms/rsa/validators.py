from algorithms.rsa.logic import is_prime, gcd, phi as _phi, modinv, encrypt as _encrypt


def _parse_int(s):
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return None


def pick_pq(input_obj, state):
    p = _parse_int(input_obj.get("p"))
    q = _parse_int(input_obj.get("q"))
    if p is None or q is None:
        return {"ok": False, "hint": "Enter whole numbers for both p and q."}
    if p == q:
        return {"ok": False, "hint": "p and q must be different primes."}
    if not (2 <= p <= 999 and 2 <= q <= 999):
        return {"ok": False, "hint": "p and q must be at most 3 digits (between 2 and 999)."}
    if not is_prime(p):
        return {"ok": False, "hint": f"{p} is not prime."}
    if not is_prime(q):
        return {"ok": False, "hint": f"{q} is not prime."}
    return {"ok": True, "value": {"p": p, "q": q}}


def compute_n(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    expected = state["p"] * state["q"]
    if got != expected:
        return {"ok": False, "hint": f"n = p · q. With p={state['p']}, q={state['q']}."}
    return {"ok": True, "value": {"n": got}}


def compute_phi(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    expected = _phi(state["p"], state["q"])
    if got != expected:
        return {"ok": False, "hint": f"φ(n) = (p-1)(q-1). With p={state['p']}, q={state['q']}."}
    return {"ok": True, "value": {"phi": got}}


def pick_e(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    if not (1 < got < state["phi"]):
        return {"ok": False, "hint": f"e must satisfy 1 < e < φ(n) = {state['phi']}."}
    if gcd(got, state["phi"]) != 1:
        return {"ok": False, "hint": f"e must be coprime to φ(n). gcd({got}, {state['phi']}) ≠ 1."}
    return {"ok": True, "value": {"e": got}}


def compute_d(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    expected = modinv(state["e"], state["phi"])
    if got != expected:
        return {"ok": False, "hint": f"d satisfies (d · e) ≡ 1 (mod φ). With e={state['e']}, φ={state['phi']}."}
    return {"ok": True, "value": {"d": got}}


def pick_message(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    if not (0 <= got < state["n"]):
        return {"ok": False, "hint": f"Message must satisfy 0 ≤ m < n = {state['n']}."}
    return {"ok": True, "value": {"m": got}}


def encrypt(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    expected = _encrypt(state["m"], state["e"], state["n"])
    if got != expected:
        return {"ok": False, "hint": f"c = m^e mod n. With m={state['m']}, e={state['e']}, n={state['n']}."}
    return {"ok": True, "value": {"c": got}}


def decrypt(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    expected = pow(state["c"], state["d"], state["n"])
    if got != expected:
        return {"ok": False, "hint": f"m = c^d mod n. With c={state['c']}, d={state['d']}, n={state['n']}."}
    return {"ok": True, "value": {"m_decrypted": got}}


def info(_input, _state):
    return {"ok": True, "value": {}}


def _pick_e_deterministic(phi):
    e = 3
    while gcd(e, phi) != 1:
        e += 1
    return e


def pick_pq_big(input_obj, state):
    p = _parse_int(input_obj.get("p"))
    q = _parse_int(input_obj.get("q"))
    if p is None or q is None:
        return {"ok": False, "hint": "Enter whole numbers for both p and q."}
    if p < 17 or q < 17:
        return {"ok": False, "hint": "For real text, both primes need to be at least 17 so n ≥ 256."}
    if p == q:
        return {"ok": False, "hint": "p and q must be different primes."}
    if not is_prime(p):
        return {"ok": False, "hint": f"{p} is not prime."}
    if not is_prime(q):
        return {"ok": False, "hint": f"{q} is not prime."}
    n2 = p * q
    if n2 < 256:
        return {"ok": False, "hint": "n must be at least 256 to fit any ASCII character."}
    phi2 = (p - 1) * (q - 1)
    e2 = _pick_e_deterministic(phi2)
    d2 = modinv(e2, phi2)
    return {"ok": True, "value": {
        "p2": p, "q2": q, "n2": n2, "phi2": phi2, "e2": e2, "d2": d2,
    }}


def pick_sentence(input_str, state):
    s = "" if input_str is None else str(input_str)
    if len(s) == 0:
        return {"ok": False, "hint": "Type at least one character."}
    if len(s) > 500:
        return {"ok": False, "hint": "Keep it under 500 characters."}
    for ch in s:
        code = ord(ch)
        if code < 32 or code > 126:
            return {"ok": False, "hint": f"Only printable ASCII for now — no emoji, accents, tabs, or newlines. Found: {ch!r}."}
    return {"ok": True, "value": {"sentence": s}}


def encrypt_sentence_head(input_str, state):
    got = _parse_int(input_str)
    if got is None:
        return {"ok": False, "hint": "Enter a whole number."}
    sentence = state.get("sentence", "")
    if not sentence:
        return {"ok": False, "hint": "No sentence in state — go back and type one first."}
    first_code = ord(sentence[0])
    e2, n2 = state["e2"], state["n2"]
    expected_first = pow(first_code, e2, n2)
    if got != expected_first:
        return {"ok": False, "hint": f"c = m^e mod n. With m={first_code} (the ASCII of {sentence[0]!r}), e={e2}, n={n2}."}
    encrypted = [pow(ord(ch), e2, n2) for ch in sentence]
    return {"ok": True, "value": {"encrypted": encrypted}}
