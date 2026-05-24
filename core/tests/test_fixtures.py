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
