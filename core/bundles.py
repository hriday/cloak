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
        "stations": [
            {
                "algorithm": "x25519",
                "prose": (
                    "You type `https://example.com` into your browser. The first thing your browser does — "
                    "before sending a single byte of the request, before even confirming the server is who it "
                    "says it is — is **agree on a shared secret** with a complete stranger over an open network.\n\n"
                    "This is the impossible-sounding feat that Diffie and Hellman solved in 1976 and that Daniel "
                    "Bernstein modernized in 2005 with **Curve25519**. The browser picks a random private key, "
                    "computes the public key (one elliptic-curve scalar multiplication, ~30 microseconds), and "
                    "sends the public key to the server in the `ClientHello`. The server does the same and "
                    "replies in the `ServerHello`. Both sides now multiply their own private key by the other's "
                    "public key, and — by the algebra of the curve — get the **same 32 bytes**. An attacker "
                    "watching the wire sees both public keys and can't compute the shared secret.\n\n"
                    "TLS 1.3 mandates X25519 (or P-256) for this step; the older `RSA` key-exchange ciphersuites "
                    "from TLS 1.2 are GONE — no forward secrecy was the deal-breaker. With X25519, the private "
                    "keys are ephemeral (generated fresh per connection, discarded after), so even if the server "
                    "is compromised tomorrow, recorded traffic from today can't be decrypted retroactively. "
                    "That's **forward secrecy**, and it falls out for free from making the key exchange "
                    "ephemeral."
                ),
            },
            {
                "algorithm": "chacha20-poly1305",
                "prose": (
                    "32 bytes of shared secret. Now what?\n\n"
                    "TLS 1.3 feeds it into **HKDF** (extract-then-expand) to derive a tree of working keys: a "
                    "`client_application_traffic_secret`, a `server_application_traffic_secret`, IVs, "
                    "exporter secrets, resumption secrets. From each traffic secret, HKDF-Expand produces a "
                    "concrete AEAD key + initial IV.\n\n"
                    "The actual record encryption is **AES-128-GCM** or **ChaCha20-Poly1305** (the client "
                    "advertises preference; on mobile, where AES-NI isn't available, ChaCha20 wins because it's "
                    "faster in software). Both are AEAD constructions — they encrypt and authenticate in one "
                    "pass. Every record gets its own nonce (derived from the IV XOR the sequence number), and "
                    "the 16-byte tag at the end catches *any* tampering. Flip a bit in transit and decryption "
                    "throws `InvalidTag`.\n\n"
                    "Why two AEADs and not just AES-GCM? Diversity. If a flaw is found in AES-GCM's tag (Joux's "
                    "forbidden-attack class) or in GHASH polynomial arithmetic, ChaCha20-Poly1305 is the "
                    "drop-in replacement using a structurally different MAC (polynomial in a prime field, not "
                    "Galois field). The internet doesn't have to wait for a panic redeploy."
                ),
            },
            {
                "algorithm": "ed25519",
                "prose": (
                    "We've got a confidential, integrity-protected channel. But to *who*? X25519 establishes a "
                    "shared secret with **some** entity — there's nothing stopping an attacker from doing the "
                    "key exchange themselves and serving you a fake `example.com`. The browser needs to verify "
                    "**identity**.\n\n"
                    "After the key exchange, the server sends a `Certificate` message: an X.509 certificate "
                    "chain signed by a Certificate Authority the browser trusts. Modern certificates use "
                    "**Ed25519** or **ECDSA P-256** signatures on the leaf cert (RSA-2048 is still common but "
                    "shrinking; the CA roots are still mostly RSA). The browser verifies the chain: leaf signed "
                    "by intermediate, intermediate signed by root, root in the trust store.\n\n"
                    "Then the server signs a `CertificateVerify`: an Ed25519 signature over a transcript hash "
                    "of every handshake message so far. This proves the server holds the private key matching "
                    "the public key in its certificate AND that it saw the same handshake bytes the client did "
                    "(no man-in-the-middle splicing). The browser verifies. Handshake complete.\n\n"
                    "Total round trips for a fresh TLS 1.3 connection: **one**. ClientHello and ServerHello + "
                    "Certificate + CertificateVerify + Finished happen in 1.5 RTT. If the client and server "
                    "have a pre-shared key from a prior session, it's **zero RTT** — the first application data "
                    "byte can ride in the ClientHello."
                ),
            },
        ],
        "outro": (
            "Three primitives, one handshake. The hardest part of TLS 1.3 isn't the math — each of those "
            "individual algorithms is straightforward — it's the **composition**: getting the key derivation "
            "right, transcript-binding the signature so swapped messages get caught, sequencing the records so "
            "replay attacks fail, getting forward secrecy by making the right things ephemeral.\n\n"
            "Want the full RFC? [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) is the spec. It's "
            "160 pages. Now that you've walked the underlying algorithms, it should read like a recipe rather "
            "than a foreign language."
        ),
    },
    {
        "slug": "how-https-works",
        "title": "How HTTPS works (the classic story)",
        "tagline": "The older RSA-based TLS handshake, still useful to understand. Two strangers meet on the internet and build a secure channel — asymmetric meets symmetric.",
        "algorithms": ["rsa", "aes", "hybrid"],
    },
    {
        "slug": "why-crypto-looks-weird",
        "title": "Why crypto looks weird",
        "tagline": "The attacks that motivated the design choices in the rest of the catalog. Padding oracles. ECB penguins. Length extension. PS3 nonce reuse. Each one is a reason something is built the way it is.",
        "algorithms": ["padding-oracle", "length-extension", "cipher-modes", "ecdsa"],
    },
    {
        "slug": "post-quantum-primer",
        "title": "Post-quantum primer",
        "tagline": "Shor's algorithm breaks RSA, ECDH, and ECDSA on a fault-tolerant quantum computer. Kyber is what TLS and Signal are migrating to.",
        "algorithms": ["kyber", "x25519"],
    },
    {
        "slug": "hashing-for-developers",
        "title": "Hashing for developers",
        "tagline": "SHA-256 fingerprints data; HMAC authenticates messages; HKDF derives keys; SHA-3 is the alternative when you want diversity. Plus password hashing for database leaks.",
        "algorithms": ["sha256", "sha3", "hmac", "hkdf", "password-hashing"],
    },
    {
        "slug": "first-cryptography-lesson",
        "title": "Where to start",
        "tagline": "If you've never touched cryptography, start here. Caesar through one-time pad — all the ciphers that broke, and one (the OTP) that's mathematically perfect but impractical.",
        "algorithms": ["classical-ciphers"],
    },
    {
        "slug": "signatures-old-to-new",
        "title": "Signatures, classical to modern",
        "tagline": "Sign with a private key, verify with a public one. From RSA's textbook math through ECDSA's nonce-reuse footguns to the elegant Schnorr / Ed25519 design family.",
        "algorithms": ["rsa", "ecdsa", "schnorr", "ed25519"],
    },
    {
        "slug": "key-exchange-classical-to-modern",
        "title": "Key exchange, classical to modern",
        "tagline": "Diffie-Hellman invented the public-key handshake in 1976. Fifty years and one curve later, X25519 is what everyone uses.",
        "algorithms": ["diffie-hellman", "x25519", "kyber"],
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
        "tagline": "How AES became the standard. The 30-year story from DES's deathbed through Blowfish and Twofish to ChaCha20 — plus the modes that make it work.",
        "algorithms": ["triple-des", "blowfish", "twofish", "aes", "chacha20-poly1305", "cipher-modes"],
    },
]


def resolve_bundles(algorithms_by_slug):
    """Given a dict {slug: Algorithm} of live algorithms, return a list of
    bundles with algorithms resolved to Algorithm objects (in order). Bundles
    with zero resolvable algorithms are dropped — a half-empty bundle is worse
    than no bundle. A bundle is *kept* (with reduced length) if at least one
    algorithm in it is live; the others are silently skipped. The `has_essay`
    flag tells the landing template whether to link to /journeys/<slug>/
    (narrative essay) or deep-link to the first algorithm (legacy behavior)."""
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
            "has_essay": bool(b.get("stations")),
        })
    return resolved
