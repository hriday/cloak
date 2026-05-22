import pytest
from django.urls import reverse
from core.models import Algorithm


@pytest.mark.django_db
def test_landing_lists_live_algorithm(client):
    Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    resp = client.get(reverse("landing"))
    assert resp.status_code == 200
    assert b"RSA" in resp.content
    assert b"More algorithms coming soon" in resp.content


@pytest.mark.django_db
def test_landing_dims_coming_soon(client):
    Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    resp = client.get(reverse("landing"))
    assert b'class="card muted"' in resp.content


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
