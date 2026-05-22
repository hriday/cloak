import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from core.models import Algorithm, Lesson, Step, UserProgress


@pytest.mark.django_db
def test_algorithm_slug_unique():
    Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    with pytest.raises(IntegrityError):
        Algorithm.objects.create(slug="rsa", name="RSA 2", family="asymmetric", status="live", order=2)


@pytest.mark.django_db
def test_lesson_belongs_to_algorithm():
    algo = Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    lesson = Lesson.objects.create(algorithm=algo, slug="encrypt-decrypt", title="Encrypt & Decrypt", order=1)
    assert lesson.algorithm == algo
    assert str(lesson) == "RSA — Encrypt & Decrypt"


@pytest.mark.django_db
def test_step_ordering_unique_within_lesson():
    algo = Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    lesson = Lesson.objects.create(algorithm=algo, slug="encrypt-decrypt", title="t", order=1)
    Step.objects.create(lesson=lesson, order=1, slug="pick-pq", kind="input-multi",
                        prompt_template="pick p,q", validator_key="pick_pq", codegen_key="pick_pq")
    with pytest.raises(IntegrityError):
        Step.objects.create(lesson=lesson, order=1, slug="pick-pq-2", kind="input-multi",
                            prompt_template="x", validator_key="x", codegen_key="x")


@pytest.mark.django_db
def test_user_progress_state_is_jsonb():
    User = get_user_model()
    user = User.objects.create_user(username="u", email="u@e.com", password="pw")
    algo = Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    lesson = Lesson.objects.create(algorithm=algo, slug="enc", title="t", order=1)
    progress = UserProgress.objects.create(
        user=user, lesson=lesson, current_step_order=3, state={"p": 61, "q": 53, "n": 3233}
    )
    progress.refresh_from_db()
    assert progress.state["p"] == 61
    assert progress.state["n"] == 3233
