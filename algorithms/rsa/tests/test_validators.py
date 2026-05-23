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
