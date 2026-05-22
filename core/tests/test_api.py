import json
import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from core.models import Algorithm, Lesson, Step, UserProgress


@pytest.fixture
def rsa_lesson(db):
    algo = Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    lesson = Lesson.objects.create(algorithm=algo, slug="encrypt-decrypt", title="t", order=1)
    for i, slug in enumerate(["pick-pq", "compute-n"], start=1):
        Step.objects.create(lesson=lesson, order=i, slug=slug, kind="info",
                            prompt_template="x", validator_key=slug.replace("-", "_"), codegen_key=slug.replace("-", "_"))
    return lesson


@pytest.fixture
def logged_in_client(client, db):
    User = get_user_model()
    user = User.objects.create_user(username="u", email="u@e.com", password="pw")
    client.force_login(user)
    return client, user


@pytest.mark.django_db
def test_post_progress_creates_row(logged_in_client, rsa_lesson):
    client, user = logged_in_client
    resp = client.post(
        f"/api/progress/{rsa_lesson.slug}/",
        data=json.dumps({"state": {"p": 61, "q": 53}, "current_step_order": 2}),
        content_type="application/json",
    )
    assert resp.status_code == 200, resp.content
    progress = UserProgress.objects.get(user=user, lesson=rsa_lesson)
    assert progress.state == {"p": 61, "q": 53}
    assert progress.current_step_order == 2


@pytest.mark.django_db
def test_post_progress_rejects_tampered_state(logged_in_client, rsa_lesson):
    client, _ = logged_in_client
    # Claim phi inconsistent with p, q
    resp = client.post(
        f"/api/progress/{rsa_lesson.slug}/",
        data=json.dumps({"state": {"p": 61, "q": 53, "n": 9999}, "current_step_order": 3}),
        content_type="application/json",
    )
    assert resp.status_code == 400


@pytest.mark.django_db
def test_get_progress(logged_in_client, rsa_lesson):
    client, user = logged_in_client
    UserProgress.objects.create(user=user, lesson=rsa_lesson, current_step_order=2, state={"p": 7, "q": 11})
    resp = client.get(f"/api/progress/{rsa_lesson.slug}/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["state"] == {"p": 7, "q": 11}
    assert body["current_step_order"] == 2


@pytest.mark.django_db
def test_anonymous_blocked(client, rsa_lesson):
    resp = client.get(f"/api/progress/{rsa_lesson.slug}/")
    assert resp.status_code in (401, 403)


@pytest.mark.django_db
def test_import_merges_localstorage(logged_in_client, rsa_lesson):
    client, user = logged_in_client
    payload = {
        "items": [
            {"lesson_slug": rsa_lesson.slug, "state": {"p": 61, "q": 53}, "current_step_order": 2},
        ]
    }
    resp = client.post("/api/progress/import/", data=json.dumps(payload), content_type="application/json")
    assert resp.status_code == 200
    progress = UserProgress.objects.get(user=user, lesson=rsa_lesson)
    assert progress.current_step_order == 2
