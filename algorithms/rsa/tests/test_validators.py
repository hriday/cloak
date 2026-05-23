import pytest
from algorithms.rsa import validators as v


def test_pick_pq_happy():
    r = v.pick_pq({"p": "61", "q": "53"}, {})
    assert r == {"ok": True, "value": {"p": 61, "q": 53}}


def test_pick_pq_rejects_non_prime():
    r = v.pick_pq({"p": "60", "q": "53"}, {})
    assert r["ok"] is False
    assert "prime" in r["hint"].lower()


def test_pick_pq_rejects_equal_p_q():
    r = v.pick_pq({"p": "61", "q": "61"}, {})
    assert r["ok"] is False
    assert r["hint"]


def test_pick_pq_rejects_too_large():
    r = v.pick_pq({"p": "1009", "q": "53"}, {})  # 4 digits
    assert r["ok"] is False


def test_pick_pq_rejects_degenerate_pair():
    # (2, 3) gives phi = 2, which leaves no integer e with 1 < e < phi.
    # The lesson is unfinishable from this state, so reject upfront.
    r = v.pick_pq({"p": "2", "q": "3"}, {})
    assert r["ok"] is False
    assert any(t in r["hint"].lower() for t in ("too small", "larger primes", "φ", "phi"))


def test_compute_n_happy():
    r = v.compute_n("3233", {"p": 61, "q": 53})
    assert r == {"ok": True, "value": {"n": 3233}}


def test_compute_n_wrong():
    r = v.compute_n("3000", {"p": 61, "q": 53})
    assert r["ok"] is False


def test_compute_phi_happy():
    r = v.compute_phi("3120", {"p": 61, "q": 53})
    assert r == {"ok": True, "value": {"phi": 3120}}


def test_pick_e_accepts_any_coprime():
    r = v.pick_e("17", {"phi": 3120})
    assert r == {"ok": True, "value": {"e": 17}}


def test_pick_e_rejects_non_coprime():
    r = v.pick_e("6", {"phi": 3120})
    assert r["ok"] is False


def test_compute_d_happy():
    r = v.compute_d("2753", {"e": 17, "phi": 3120})
    assert r == {"ok": True, "value": {"d": 2753}}


def test_compute_d_wrong():
    r = v.compute_d("99", {"e": 17, "phi": 3120})
    assert r["ok"] is False


def test_pick_message_must_be_less_than_n():
    r = v.pick_message("65", {"n": 3233})
    assert r == {"ok": True, "value": {"m": 65}}
    bad = v.pick_message("4000", {"n": 3233})
    assert bad["ok"] is False


def test_encrypt_happy():
    r = v.encrypt(str(pow(65, 17, 3233)), {"m": 65, "e": 17, "n": 3233})
    assert r["ok"] is True


def test_decrypt_happy():
    c = pow(65, 17, 3233)
    r = v.decrypt("65", {"c": c, "d": 2753, "n": 3233})
    assert r == {"ok": True, "value": {"m_decrypted": 65}}


def test_pick_pq_big_happy():
    result = v.pick_pq_big({"p": "17", "q": "19"}, {})
    assert result["ok"] is True
    val = result["value"]
    assert val["p2"] == 17 and val["q2"] == 19
    assert val["n2"] == 323
    assert val["phi2"] == 288
    assert val["e2"] == 5  # smallest int >= 3 coprime to 288
    assert val["d2"] == 173  # modinv(5, 288)


def test_pick_pq_big_rejects_too_small():
    r = v.pick_pq_big({"p": "11", "q": "19"}, {})
    assert r["ok"] is False
    assert "at least 17" in r["hint"]


def test_pick_pq_big_rejects_equal():
    r = v.pick_pq_big({"p": "17", "q": "17"}, {})
    assert r["ok"] is False
    assert "different" in r["hint"]


def test_pick_pq_big_rejects_non_prime():
    r = v.pick_pq_big({"p": "17", "q": "21"}, {})
    assert r["ok"] is False
    assert "21" in r["hint"] and "prime" in r["hint"]


def test_pick_sentence_happy():
    r = v.pick_sentence("Hello, world!", {})
    assert r["ok"] is True
    assert r["value"]["sentence"] == "Hello, world!"
    assert r["value"]["first_char"] == "H"
    assert r["value"]["first_code"] == 72


def test_pick_sentence_rejects_empty():
    r = v.pick_sentence("", {})
    assert r["ok"] is False
    assert "at least one" in r["hint"]


def test_pick_sentence_rejects_too_long():
    r = v.pick_sentence("a" * 501, {})
    assert r["ok"] is False
    assert "500" in r["hint"]


def test_pick_sentence_rejects_emoji():
    r = v.pick_sentence("Hi 🦊", {})
    assert r["ok"] is False
    assert "ASCII" in r["hint"] or "ascii" in r["hint"]


def test_pick_sentence_rejects_newline():
    r = v.pick_sentence("Line1\nLine2", {})
    assert r["ok"] is False


def test_encrypt_sentence_head_happy():
    # state from "Hi" with p=17, q=19, e=5, n=323
    state = {"sentence": "Hi", "e2": 5, "n2": 323, "d2": 173}
    # 72^5 mod 323 = ?
    expected_first = pow(72, 5, 323)
    r = v.encrypt_sentence_head(str(expected_first), state)
    assert r["ok"] is True
    enc = r["value"]["encrypted"]
    assert len(enc) == 2
    assert enc[0] == expected_first
    assert enc[1] == pow(105, 5, 323)


def test_encrypt_sentence_head_wrong():
    state = {"sentence": "Hi", "e2": 5, "n2": 323, "d2": 173}
    r = v.encrypt_sentence_head("999", state)
    assert r["ok"] is False
    assert "72" in r["hint"]  # mentions m = 72
    assert "5" in r["hint"]   # mentions e
    assert "323" in r["hint"] # mentions n
