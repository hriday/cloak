import pytest
from algorithms.rsa.logic import is_prime, gcd, phi, modinv, encrypt, decrypt, coprime_candidates


def test_is_prime():
    assert is_prime(2)
    assert is_prime(61)
    assert is_prime(997)
    assert not is_prime(1)
    assert not is_prime(0)
    assert not is_prime(-7)
    assert not is_prime(60)


def test_gcd():
    assert gcd(48, 18) == 6
    assert gcd(17, 5) == 1


def test_phi():
    assert phi(61, 53) == 3120


def test_modinv():
    assert modinv(17, 3120) == 2753
    assert (17 * 2753) % 3120 == 1


def test_modinv_no_inverse_raises():
    with pytest.raises(ValueError):
        modinv(6, 9)  # gcd != 1


def test_encrypt_decrypt_roundtrip():
    e, n, d = 17, 3233, 2753
    c = encrypt(65, e, n)
    assert c == pow(65, e, n)
    assert decrypt(c, d, n) == 65


def test_coprime_candidates():
    cands = coprime_candidates(3120, limit=10)
    assert all(gcd(c, 3120) == 1 for c in cands)
    assert 1 not in cands
    assert all(c < 3120 for c in cands)
    assert len(cands) == 10
