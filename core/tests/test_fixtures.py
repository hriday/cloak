import pytest
from django.core.management import call_command
from core.models import Algorithm, Lesson, Step


@pytest.mark.django_db
def test_rsa_fixture_loads():
    call_command("loaddata", "algorithms/rsa/fixtures.json")
    algo = Algorithm.objects.get(slug="rsa")
    assert algo.status == "live"
    lesson = Lesson.objects.get(algorithm=algo, slug="encrypt-decrypt")
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 15
    assert [s.slug for s in steps] == [
        "intro", "pick-pq", "compute-n", "compute-phi", "pick-e",
        "compute-d", "pick-message", "encrypt", "decrypt-done", "toy-complete",
        "pick-big-primes", "type-sentence", "encrypt-sentence", "decrypt-sentence", "done",
    ]


@pytest.mark.django_db
def test_hybrid_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/hybrid/fixtures.json")

    from core.models import Algorithm, Lesson, Step
    assert Algorithm.objects.filter(slug="hybrid").count() == 1
    algo = Algorithm.objects.get(slug="hybrid")
    assert algo.name == "Hybrid Encryption"
    assert algo.family == "asymmetric"
    assert algo.status == "live"

    lesson = Lesson.objects.get(algorithm=algo, slug="wrap-and-send")
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 9
    assert [s.slug for s in steps] == [
        "intro", "meet-symmetric", "pick-sym-key", "wrap-key",
        "type-message", "xor-encrypt", "unwrap-key", "xor-decrypt", "done",
    ]
    # Spot-check validator keys for the actionable steps
    by_slug = {s.slug: s for s in steps}
    assert by_slug["pick-sym-key"].validator_key == "pick_sym_key"
    assert by_slug["wrap-key"].validator_key == "wrap_key"
    assert by_slug["type-message"].validator_key == "type_message"
    assert by_slug["xor-encrypt"].validator_key == "xor_encrypt_head"
    assert by_slug["unwrap-key"].validator_key == "unwrap_key"
    assert by_slug["xor-decrypt"].validator_key == "xor_decrypt_head"


@pytest.mark.django_db
def test_aes_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/aes/fixtures.json")

    from core.models import Algorithm, Lesson, Step
    assert Algorithm.objects.filter(slug="aes").count() == 1
    algo = Algorithm.objects.get(slug="aes")
    assert algo.name == "AES"
    assert algo.family == "symmetric"
    assert algo.status == "live"

    lesson = Lesson.objects.get(algorithm=algo, slug="four-transformations")
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 8
    assert [s.slug for s in steps] == [
        "intro", "sub-bytes", "shift-rows", "mix-columns",
        "add-round-key", "one-real-round", "encrypt-a-message", "done",
    ]
    by_slug = {s.slug: s for s in steps}
    assert by_slug["sub-bytes"].validator_key == "sub_byte"
    assert by_slug["shift-rows"].validator_key == "shift_row"
    assert by_slug["add-round-key"].validator_key == "add_round_key"
    assert by_slug["encrypt-a-message"].validator_key == "pick_aes_message"


@pytest.mark.django_db
def test_3des_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/triple-des/fixtures.json")

    from core.models import Algorithm, Lesson, Step
    assert Algorithm.objects.filter(slug="triple-des").count() == 1
    algo = Algorithm.objects.get(slug="triple-des")
    assert algo.name == "Triple DES"
    assert algo.family == "symmetric"

    lesson = Lesson.objects.get(algorithm=algo, slug="why-3des")
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 7
    assert [s.slug for s in steps] == [
        "intro", "single-des-weakness", "naive-2des-intro",
        "mitm-attack", "3des-ede", "encrypt-with-3des", "done",
    ]
    by_slug = {s.slug: s for s in steps}
    assert by_slug["mitm-attack"].validator_key == "mitm_attack"
    assert by_slug["mitm-attack"].kind == "input-multi"
    assert by_slug["encrypt-with-3des"].validator_key == "pick_3des_message"
    assert by_slug["encrypt-with-3des"].kind == "input-text"


@pytest.mark.django_db
def test_hsm_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/hsm/fixtures.json")

    from core.models import Algorithm, Lesson, Step
    assert Algorithm.objects.filter(slug="hsm").count() == 1
    algo = Algorithm.objects.get(pk=5)
    assert algo.slug == "hsm"
    assert algo.name == "HSM"
    assert algo.family == "hsm"
    assert algo.status == "live"

    lesson = Lesson.objects.get(pk=5)
    assert lesson.algorithm_id == 5
    assert lesson.slug == "key-vaults"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 10
    assert [s.slug for s in steps] == [
        "intro", "the-vault-analogy", "operations-api", "simulated-hsm",
        "kek-hierarchy", "real-world-kms",
        "payment-hsms", "pin-translation",
        "where-required", "done",
    ]
    by_slug = {s.slug: s for s in steps}
    assert by_slug["simulated-hsm"].kind == "input-text"
    assert by_slug["simulated-hsm"].validator_key == "hsm_operation"
    assert by_slug["payment-hsms"].kind == "info"
    assert by_slug["pin-translation"].kind == "input-numeric"
    assert by_slug["pin-translation"].validator_key == "pin_translation"
    # Step 7 must include the Thales payShield 10K table for the banking treatment
    assert "payShield 10K" in by_slug["payment-hsms"].prompt_template
    assert "PIN_Translate" in by_slug["payment-hsms"].prompt_template
    # Step 8 must show the ISO 9564 Format 0 PIN block diagram
    assert "ISO 9564" in by_slug["pin-translation"].prompt_template


@pytest.mark.django_db
def test_blowfish_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/blowfish/fixtures.json")

    from core.models import Algorithm, Lesson, Step
    assert Algorithm.objects.filter(slug="blowfish").count() == 1
    algo = Algorithm.objects.get(pk=6)
    assert algo.slug == "blowfish"
    assert algo.name == "Blowfish"
    assert algo.family == "symmetric"
    assert algo.status == "live"

    lesson = Lesson.objects.get(pk=6)
    assert lesson.algorithm_id == 6
    assert lesson.slug == "feistel-rounds"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 6
    assert [s.slug for s in steps] == [
        "intro", "feistel-structure", "f-function",
        "one-round", "encrypt-a-message", "done",
    ]
    by_slug = {s.slug: s for s in steps}
    assert by_slug["f-function"].kind == "input-numeric"
    assert by_slug["f-function"].validator_key == "f_function"


@pytest.mark.django_db
def test_twofish_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/twofish/fixtures.json")

    from core.models import Algorithm, Lesson, Step
    assert Algorithm.objects.filter(slug="twofish").count() == 1
    algo = Algorithm.objects.get(pk=7)
    assert algo.slug == "twofish"
    assert algo.name == "Twofish"
    assert algo.family == "symmetric"
    assert algo.status == "live"

    lesson = Lesson.objects.get(pk=7)
    assert lesson.algorithm_id == 7
    assert lesson.slug == "aes-finalist"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 6
    assert [s.slug for s in steps] == [
        "intro", "vs-aes", "key-dependent-sboxes",
        "whitening", "encrypt-a-message", "done",
    ]
    by_slug = {s.slug: s for s in steps}
    assert by_slug["whitening"].kind == "input-numeric"
    assert by_slug["whitening"].validator_key == "whitening"
    # Step 2 prompt contains a markdown table.
    vs_aes_prompt = by_slug["vs-aes"].prompt_template
    assert "|" in vs_aes_prompt
    assert "---" in vs_aes_prompt


@pytest.mark.django_db
def test_sha256_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/sha256/fixtures.json")

    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=8)
    assert algo.slug == "sha256"
    assert algo.name == "SHA-256"
    assert algo.family == "hash"
    assert algo.status == "live"
    assert len(algo.intro_template) <= 200

    lesson = Lesson.objects.get(pk=8)
    assert lesson.algorithm_id == 8
    assert lesson.slug == "walk-the-hash"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 8
    assert [s.slug for s in steps] == [
        "intro", "preprocessing", "init-state", "compression",
        "walk-empty", "avalanche", "hash-a-sentence", "done",
    ]
    by_slug = {s.slug: s for s in steps}
    assert by_slug["walk-empty"].kind == "input-text"
    assert by_slug["walk-empty"].validator_key == "walk_empty_hash"
    assert by_slug["hash-a-sentence"].validator_key == "pick_sha_sentence"


@pytest.mark.django_db
def test_hmac_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/hmac/fixtures.json")

    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=9)
    assert algo.slug == "hmac"
    assert algo.name == "HMAC"
    assert algo.family == "hash"
    assert len(algo.intro_template) <= 200

    lesson = Lesson.objects.get(pk=9)
    assert lesson.slug == "mac-the-message"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 7
    assert [s.slug for s in steps] == [
        "intro", "naive-mac", "length-extension", "hmac-construction",
        "compute-hmac", "verify-and-tamper", "done",
    ]
    by_slug = {s.slug: s for s in steps}
    assert by_slug["compute-hmac"].validator_key == "compute_hmac"
    assert by_slug["verify-and-tamper"].validator_key == "verify_hmac"


@pytest.mark.django_db
def test_x25519_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/x25519/fixtures.json")

    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=10)
    assert algo.slug == "x25519"
    assert algo.name == "X25519"
    assert algo.family == "asymmetric"
    assert len(algo.intro_template) <= 200

    lesson = Lesson.objects.get(pk=10)
    assert lesson.slug == "key-exchange-on-a-curve"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 8
    assert [s.slug for s in steps] == [
        "intro", "classical-dh", "do-a-dh", "why-curves",
        "curve25519-spec", "clamping", "exchange-keys", "done",
    ]
    by_slug = {s.slug: s for s in steps}
    assert by_slug["do-a-dh"].validator_key == "compute_dh"
    assert by_slug["clamping"].validator_key == "clamp_byte"
    assert by_slug["exchange-keys"].validator_key == "exchange_keys"


@pytest.mark.django_db
def test_ed25519_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/ed25519/fixtures.json")

    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=11)
    assert algo.slug == "ed25519"
    assert algo.name == "Ed25519"
    assert algo.family == "asymmetric"
    assert len(algo.intro_template) <= 200

    lesson = Lesson.objects.get(pk=11)
    assert lesson.slug == "sign-with-edwards"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 7
    assert [s.slug for s in steps] == [
        "intro", "key-derivation", "sign-mechanics", "verify-mechanics",
        "sign-and-verify", "vs-rsa-comparison", "done",
    ]
    by_slug = {s.slug: s for s in steps}
    assert by_slug["sign-and-verify"].validator_key == "ed25519_operation"


@pytest.mark.django_db
def test_chacha20_poly1305_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/chacha20-poly1305/fixtures.json")

    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=12)
    assert algo.slug == "chacha20-poly1305"
    assert algo.name == "ChaCha20-Poly1305"
    assert algo.family == "symmetric"
    assert len(algo.intro_template) <= 200

    lesson = Lesson.objects.get(pk=12)
    assert lesson.slug == "arx-aead"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 7
    assert [s.slug for s in steps] == [
        "intro", "arx-design", "quarter-round", "block-function",
        "poly1305-construction", "encrypt-a-message", "done",
    ]
    by_slug = {s.slug: s for s in steps}
    assert by_slug["quarter-round"].validator_key == "quarter_round_line"
    assert by_slug["encrypt-a-message"].validator_key == "encrypt_aead"


@pytest.mark.django_db
def test_cipher_modes_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/cipher-modes/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=13)
    assert algo.slug == "cipher-modes"
    assert algo.family == "symmetric"
    assert len(algo.intro_template) <= 200
    lesson = Lesson.objects.get(pk=13)
    assert lesson.slug == "modes-around-aes"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 8
    assert [s.slug for s in steps] == [
        "intro", "ecb-penguin", "cbc-construction", "cbc-walk",
        "ctr-construction", "gcm-construction", "pick-a-mode", "done",
    ]


@pytest.mark.django_db
def test_padding_oracle_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/padding-oracle/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=14)
    assert algo.slug == "padding-oracle"
    assert algo.family == "symmetric"
    assert len(algo.intro_template) <= 200
    lesson = Lesson.objects.get(pk=14)
    assert lesson.slug == "decrypt-without-the-key"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 7
    assert [s.slug for s in steps] == [
        "intro", "pkcs7-recap", "bit-flipping", "attack-one-byte",
        "attack-full-block", "defenses", "done",
    ]


@pytest.mark.django_db
def test_password_hashing_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/password-hashing/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=15)
    assert algo.slug == "password-hashing"
    assert algo.family == "hash"
    assert len(algo.intro_template) <= 200
    lesson = Lesson.objects.get(pk=15)
    assert lesson.slug == "slow-on-purpose"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 8
    assert [s.slug for s in steps] == [
        "intro", "naive-sha256-failure", "pbkdf2", "bcrypt",
        "argon2-construction", "compare-hashes", "which-to-use", "done",
    ]


@pytest.mark.django_db
def test_diffie_hellman_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/diffie-hellman/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=16)
    assert algo.slug == "diffie-hellman"
    assert algo.family == "asymmetric"
    assert len(algo.intro_template) <= 200
    lesson = Lesson.objects.get(pk=16)
    assert lesson.slug == "the-1976-handshake"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 7
    assert [s.slug for s in steps] == [
        "intro", "modular-exp", "the-handshake", "do-a-handshake",
        "discrete-log", "real-world-params", "done",
    ]


@pytest.mark.django_db
def test_ecdsa_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/ecdsa/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=17)
    assert algo.slug == "ecdsa"
    assert algo.family == "asymmetric"
    assert len(algo.intro_template) <= 200
    lesson = Lesson.objects.get(pk=17)
    assert lesson.slug == "the-ps3-disaster"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 7
    assert [s.slug for s in steps] == [
        "intro", "curve-recap", "sign-mechanics", "verify-mechanics",
        "the-ps3-attack", "aftermath-and-defenses", "done",
    ]


@pytest.mark.django_db
def test_kyber_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/kyber/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=18)
    assert algo.slug == "kyber"
    assert algo.family == "pq"
    assert len(algo.intro_template) <= 200
    lesson = Lesson.objects.get(pk=18)
    assert lesson.slug == "lattice-kem"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 8
    assert [s.slug for s in steps] == [
        "intro", "lwe-warmup", "polynomial-rings", "keygen",
        "encapsulation", "decapsulation", "real-kyber-and-hybrid", "done",
    ]


@pytest.mark.django_db
def test_sha3_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/sha3/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=19)
    assert algo.slug == "sha3"
    assert algo.family == "hash"
    assert len(algo.intro_template) <= 200
    lesson = Lesson.objects.get(pk=19)
    assert lesson.slug == "the-sponge"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 7
    assert [s.slug for s in steps] == [
        "intro", "merkle-damgard-vs-sponge", "the-sponge-construction",
        "keccak-f", "walk-empty", "hash-a-sentence", "done",
    ]


@pytest.mark.django_db
def test_hkdf_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/hkdf/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=20)
    assert algo.slug == "hkdf"
    assert algo.family == "hash"
    assert len(algo.intro_template) <= 200
    lesson = Lesson.objects.get(pk=20)
    assert lesson.slug == "extract-then-expand"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 6


@pytest.mark.django_db
def test_length_extension_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/length-extension/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=21)
    assert algo.slug == "length-extension"
    assert algo.family == "hash"
    assert len(algo.intro_template) <= 200
    lesson = Lesson.objects.get(pk=21)
    assert lesson.slug == "forge-without-the-key"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 7


@pytest.mark.django_db
def test_classical_ciphers_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/classical-ciphers/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=22)
    assert algo.slug == "classical-ciphers"
    assert algo.family == "historical"
    assert len(algo.intro_template) <= 200
    lesson = Lesson.objects.get(pk=22)
    assert lesson.slug == "before-modern"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 9


@pytest.mark.django_db
def test_schnorr_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/schnorr/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=23)
    assert algo.slug == "schnorr"
    assert algo.family == "asymmetric"
    assert len(algo.intro_template) <= 200
    lesson = Lesson.objects.get(pk=23)
    assert lesson.slug == "four-line-signature"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 7
    by_slug = {s.slug: s for s in steps}
    assert "schnorr-sign-and-verify" in by_slug  # renamed to avoid Ed25519 collision
    assert by_slug["schnorr-sign-and-verify"].validator_key == "schnorr_operation"


@pytest.mark.django_db
def test_elliptic_curves_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/elliptic-curves/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    algo = Algorithm.objects.get(pk=24)
    assert algo.slug == "elliptic-curves"
    assert algo.family == "asymmetric"
    assert len(algo.intro_template) <= 200
    lesson = Lesson.objects.get(pk=24)
    assert lesson.slug == "curves-visually"
    steps = list(Step.objects.filter(lesson=lesson).order_by("order"))
    assert len(steps) == 8
    expected = [
        "intro", "the-curve", "point-addition", "point-doubling",
        "scalar-multiplication", "finite-field-curve",
        "discrete-log-problem", "done",
    ]
    assert [s.slug for s in steps] == expected


@pytest.mark.django_db
def test_dilithium_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/dilithium/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    a = Algorithm.objects.get(pk=25)
    assert a.slug == "dilithium" and a.family == "pq" and len(a.intro_template) <= 200
    l = Lesson.objects.get(pk=25)
    assert l.slug == "lattice-signatures"
    assert Step.objects.filter(lesson=l).count() == 8


@pytest.mark.django_db
def test_sphincs_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/sphincs-plus/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    a = Algorithm.objects.get(pk=26)
    assert a.slug == "sphincs-plus" and a.family == "pq" and len(a.intro_template) <= 200
    l = Lesson.objects.get(pk=26)
    assert l.slug == "hash-based-signatures"
    assert Step.objects.filter(lesson=l).count() == 8


@pytest.mark.django_db
def test_bleichenbacher_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/bleichenbacher/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    a = Algorithm.objects.get(pk=27)
    assert a.slug == "bleichenbacher" and a.family == "asymmetric" and len(a.intro_template) <= 200
    l = Lesson.objects.get(pk=27)
    assert l.slug == "million-message-attack"
    assert Step.objects.filter(lesson=l).count() == 7


@pytest.mark.django_db
def test_collisions_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/collisions/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    a = Algorithm.objects.get(pk=28)
    assert a.slug == "collisions" and a.family == "hash" and len(a.intro_template) <= 200
    l = Lesson.objects.get(pk=28)
    assert l.slug == "same-hash-different-data"
    assert Step.objects.filter(lesson=l).count() == 7


@pytest.mark.django_db
def test_birthday_attack_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/birthday-attack/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    a = Algorithm.objects.get(pk=29)
    assert a.slug == "birthday-attack" and a.family == "hash" and len(a.intro_template) <= 200
    l = Lesson.objects.get(pk=29)
    assert l.slug == "square-root-of-n"
    assert Step.objects.filter(lesson=l).count() == 6


@pytest.mark.django_db
def test_rsa_pss_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/rsa-pss/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    a = Algorithm.objects.get(pk=30)
    assert a.slug == "rsa-pss" and a.family == "asymmetric" and len(a.intro_template) <= 200
    l = Lesson.objects.get(pk=30)
    assert l.slug == "padded-rsa-signing"
    assert Step.objects.filter(lesson=l).count() == 7


@pytest.mark.django_db
def test_bcrypt_fixture_loads(db):
    from django.core.management import call_command
    call_command("loaddata", "algorithms/bcrypt/fixtures.json")
    from core.models import Algorithm, Lesson, Step
    a = Algorithm.objects.get(pk=31)
    assert a.slug == "bcrypt" and a.family == "hash" and len(a.intro_template) <= 200
    l = Lesson.objects.get(pk=31)
    assert l.slug == "slowed-down-blowfish"
    assert Step.objects.filter(lesson=l).count() == 7
