import pytest
from django.urls import reverse
from core.models import Algorithm


@pytest.mark.django_db
def test_landing_lists_live_algorithm(client):
    Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    resp = client.get(reverse("landing"))
    assert resp.status_code == 200
    assert b"RSA" in resp.content


@pytest.mark.django_db
def test_algorithm_intro_renders(client):
    algo = Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    from core.models import Lesson
    Lesson.objects.create(algorithm=algo, slug="encrypt-decrypt", title="Encrypt & Decrypt", order=1)
    resp = client.get(reverse("algorithm_intro", args=["rsa"]))
    assert resp.status_code == 200
    assert b"RSA" in resp.content
    assert b"Start the lesson" in resp.content


@pytest.mark.django_db
def test_algorithm_intro_404_for_coming_soon(client):
    Algorithm.objects.create(slug="des", name="DES", family="symmetric", status="coming-soon", order=2)
    resp = client.get(reverse("algorithm_intro", args=["des"]))
    assert resp.status_code == 404


@pytest.mark.django_db
def test_dashboard_lists_progress(client):
    from django.contrib.auth import get_user_model
    from core.models import Lesson, UserProgress
    User = get_user_model()
    user = User.objects.create_user(username="u", email="u@e.com", password="pw")
    algo = Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    lesson = Lesson.objects.create(algorithm=algo, slug="encrypt-decrypt", title="Encrypt & Decrypt", order=1)
    UserProgress.objects.create(user=user, lesson=lesson, current_step_order=4, state={"p": 61})
    client.force_login(user)
    resp = client.get(reverse("dashboard"))
    assert resp.status_code == 200
    assert b"RSA" in resp.content
    assert b"Encrypt &amp; Decrypt" in resp.content


@pytest.mark.django_db
def test_dashboard_redirects_anonymous(client):
    resp = client.get(reverse("dashboard"))
    assert resp.status_code == 302
