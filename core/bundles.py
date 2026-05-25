"""
Curated learning journeys ("bundles") for the landing page.

A bundle is a small narrative arc — 3-5 algorithms in a recommended order — that
answers a specific real-world question. Newcomers land on the home page, see a
handful of bundles, pick one, and follow the journey from end to end.

Bundles are defined in Python (not the database) because they're editorial
content, not user-editable data. Adding a new bundle means editing this file
and shipping; that's the right level of friction for a curated index.

Each bundle's `algorithms` list is a sequence of Algorithm.slug values. The
landing view resolves slugs to objects, skipping any algorithm that isn't
currently `status="live"`. That way a bundle stays valid as the catalog grows;
bundles can reference algorithms that haven't shipped yet without breaking the
page.
"""

BUNDLES = [
    {
        "slug": "how-tls-1-3-works",
        "title": "How TLS 1.3 works",
        "tagline": "The modern handshake. ECDH for key exchange, an authenticated cipher for the record stream, Ed25519 (or a CA-signed RSA cert) for identity.",
        "algorithms": ["x25519", "chacha20-poly1305", "ed25519"],
    },
    {
        "slug": "how-https-works",
        "title": "How HTTPS works (the classic story)",
        "tagline": "The older RSA-based TLS handshake, still useful to understand. Two strangers meet on the internet and build a secure channel — asymmetric meets symmetric.",
        "algorithms": ["rsa", "aes", "hybrid"],
    },
    {
        "slug": "hashing-for-developers",
        "title": "Hashing for developers",
        "tagline": "SHA-256 fingerprints data; HMAC authenticates messages. The two primitives under almost every protocol on the internet.",
        "algorithms": ["sha256", "hmac"],
    },
    {
        "slug": "how-card-payments-work",
        "title": "How card payments work",
        "tagline": "Your PIN travels through three banks. It's never decrypted along the way — only re-encrypted under fresh keys, inside tamper-evident HSMs.",
        "algorithms": ["hsm", "triple-des", "aes"],
    },
    {
        "slug": "block-ciphers-old-to-new",
        "title": "Block ciphers, old to new",
        "tagline": "How AES became the standard. The 30-year story from DES's deathbed through Blowfish and Twofish to ChaCha20.",
        "algorithms": ["triple-des", "blowfish", "twofish", "aes", "chacha20-poly1305"],
    },
]


def resolve_bundles(algorithms_by_slug):
    """Given a dict {slug: Algorithm} of live algorithms, return a list of
    bundles with algorithms resolved to Algorithm objects (in order). Bundles
    with zero resolvable algorithms are dropped — a half-empty bundle is worse
    than no bundle. A bundle is *kept* (with reduced length) if at least one
    algorithm in it is live; the others are silently skipped."""
    resolved = []
    for b in BUNDLES:
        objs = [
            algorithms_by_slug[slug]
            for slug in b["algorithms"]
            if slug in algorithms_by_slug
        ]
        if not objs:
            continue
        resolved.append({
            "slug": b["slug"],
            "title": b["title"],
            "tagline": b["tagline"],
            "algorithms": objs,
            "first": objs[0],
        })
    return resolved
