import json
import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.urls import reverse
from core.models import UserProgress


@pytest.fixture
def rsa_loaded(db):
    call_command("loaddata", "algorithms/rsa/fixtures.json")


@pytest.mark.django_db
def test_landing_intro_lesson_chain(client, rsa_loaded):
    assert client.get(reverse("landing")).status_code == 200
    assert client.get(reverse("algorithm_intro", args=["rsa"])).status_code == 200
    resp = client.get(reverse("lesson_runner", args=["rsa", "encrypt-decrypt"]))
    assert resp.status_code == 200
    assert b"RSA" in resp.content
    assert b"steps:" in resp.content or b'"order":' in resp.content  # JSON-embedded steps present


@pytest.mark.django_db
def test_logged_in_progress_full_rsa_flow(client, rsa_loaded):
    User = get_user_model()
    user = User.objects.create_user(username="u", email="u@e.com", password="pw")
    client.force_login(user)
    p, q = 61, 53
    n, phi_n = p * q, (p - 1) * (q - 1)
    e, d = 17, pow(17, -1, phi_n)
    m = 65
    c = pow(m, e, n)
    states = [
        {"p": p, "q": q},
        {"p": p, "q": q, "n": n},
        {"p": p, "q": q, "n": n, "phi": phi_n},
        {"p": p, "q": q, "n": n, "phi": phi_n, "e": e},
        {"p": p, "q": q, "n": n, "phi": phi_n, "e": e, "d": d},
        {"p": p, "q": q, "n": n, "phi": phi_n, "e": e, "d": d, "m": m},
        {"p": p, "q": q, "n": n, "phi": phi_n, "e": e, "d": d, "m": m, "c": c},
        {"p": p, "q": q, "n": n, "phi": phi_n, "e": e, "d": d, "m": m, "c": c, "m_decrypted": m},
    ]
    for i, state in enumerate(states, start=2):
        resp = client.post(
            "/api/progress/rsa/encrypt-decrypt/",
            data=json.dumps({"state": state, "current_step_order": i}),
            content_type="application/json",
        )
        assert resp.status_code == 200, f"step {i}: {resp.content}"

    # Step 10: the 'toy-complete' info step — same toy state, just an advance
    toy_state = {"p": p, "q": q, "n": n, "phi": phi_n, "e": e, "d": d, "m": m, "c": c, "m_decrypted": m}
    resp = client.post(
        "/api/progress/rsa/encrypt-decrypt/",
        data=json.dumps({"state": toy_state, "current_step_order": 10}),
        content_type="application/json",
    )
    assert resp.status_code == 200, f"step 10: {resp.content}"

    # Steps 11-15: the sentence-encryption flow
    p2, q2 = 17, 19
    n2, phi2 = p2 * q2, (p2 - 1) * (q2 - 1)
    e2, d2 = 5, 173
    sentence = "Hi"
    encrypted = [pow(72, e2, n2), pow(105, e2, n2)]

    big_primes_state = {**toy_state, "p2": p2, "q2": q2, "n2": n2, "phi2": phi2, "e2": e2, "d2": d2}
    sentence_state = {**big_primes_state, "sentence": sentence}
    encrypted_state = {**sentence_state, "encrypted": encrypted}

    later_states = [
        (11, big_primes_state),
        (12, sentence_state),
        (13, encrypted_state),
        (14, encrypted_state),
        (15, encrypted_state),
    ]
    last_body = None
    for order, state in later_states:
        resp = client.post(
            "/api/progress/rsa/encrypt-decrypt/",
            data=json.dumps({"state": state, "current_step_order": order}),
            content_type="application/json",
        )
        assert resp.status_code == 200, f"step {order}: {resp.content}"
        last_body = resp.json()

    assert last_body["completed_at"] is not None, "done step must set completed_at"

    final = UserProgress.objects.get(user=user, lesson__slug="encrypt-decrypt")
    assert final.current_step_order == 15
    assert final.state["m_decrypted"] == m
    assert final.state["sentence"] == "Hi"
    assert final.completed_at is not None, "completed_at must be persisted after done step"
