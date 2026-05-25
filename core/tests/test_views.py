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
def test_landing_groups_by_family(client):
    Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    Algorithm.objects.create(slug="aes", name="AES", family="symmetric", status="live", order=2)
    resp = client.get(reverse("landing"))
    assert resp.status_code == 200
    # Both family section headers should appear
    assert b"Asymmetric" in resp.content
    assert b"Symmetric" in resp.content
    # Empty families (post-quantum, hsm) should be hidden
    assert b"Post-quantum" not in resp.content


@pytest.mark.django_db
def test_landing_shows_bundles_when_algorithms_live(client):
    """Bundles surface on the landing once their first algorithm is live."""
    Algorithm.objects.create(slug="rsa", name="RSA", family="asymmetric", status="live", order=1)
    Algorithm.objects.create(slug="aes", name="AES", family="symmetric", status="live", order=2)
    Algorithm.objects.create(slug="hybrid", name="Hybrid Encryption", family="asymmetric", status="live", order=3)
    resp = client.get(reverse("landing"))
    # All three "How HTTPS works" algorithms live → bundle appears
    assert b"Start here" in resp.content
    assert b"How HTTPS works" in resp.content


def test_resolve_bundles_skips_missing_algorithms():
    """Bundles with partial coverage are kept (and trimmed). Bundles with no
    live algorithms are dropped."""
    from core.bundles import resolve_bundles
    class FakeAlgo:
        def __init__(self, slug):
            self.slug = slug
    only_rsa = {"rsa": FakeAlgo("rsa")}
    bundles = resolve_bundles(only_rsa)
    # "how-https-works" starts with rsa → kept with one algorithm
    https = next((b for b in bundles if b["slug"] == "how-https-works"), None)
    assert https is not None
    assert [a.slug for a in https["algorithms"]] == ["rsa"]
    # "how-card-payments-work" starts with hsm (not live) → no live algos → dropped
    payments = next((b for b in bundles if b["slug"] == "how-card-payments-work"), None)
    assert payments is None


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
