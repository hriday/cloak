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
