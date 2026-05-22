def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def phi(p: int, q: int) -> int:
    return (p - 1) * (q - 1)


def _egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError(f"no modular inverse: gcd({a}, {m}) = {g}")
    return x % m


def encrypt(m: int, e: int, n: int) -> int:
    return pow(m, e, n)


def decrypt(c: int, d: int, n: int) -> int:
    return pow(c, d, n)


def coprime_candidates(phi_n: int, limit: int = 12) -> list[int]:
    """First `limit` values e where 1 < e < phi_n and gcd(e, phi_n) == 1, starting from e = 3."""
    out = []
    e = 3
    while len(out) < limit and e < phi_n:
        if gcd(e, phi_n) == 1:
            out.append(e)
        e += 2
    return out
