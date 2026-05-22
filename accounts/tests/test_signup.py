import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse


@pytest.mark.django_db
def test_signup_creates_user(client):
    resp = client.post(reverse("signup"), {
        "username": "alice",
        "email": "alice@example.com",
        "password1": "correcthorsebattery",
        "password2": "correcthorsebattery",
    })
    assert resp.status_code in (302, 200)
    User = get_user_model()
    assert User.objects.filter(username="alice").exists()


@pytest.mark.django_db
def test_signup_rejects_mismatched_passwords(client):
    resp = client.post(reverse("signup"), {
        "username": "alice", "email": "a@b.com",
        "password1": "correcthorsebattery", "password2": "wrong",
    })
    User = get_user_model()
    assert not User.objects.filter(username="alice").exists()
    assert resp.status_code == 200
