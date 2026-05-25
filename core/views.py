from collections import OrderedDict

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404
from .bundles import resolve_bundles
from .models import Algorithm, Lesson, UserProgress


# Display order + label for family sections on the landing. Hidden if empty.
# Order matches a rough "easy → exotic" pedagogical progression.
FAMILY_SECTIONS = [
    ("historical", "Historical / pre-modern", "Where cryptography started — substitution and shift ciphers, frequency analysis, the one-time pad. The on-ramp."),
    ("asymmetric", "Asymmetric", "Public/private keypairs. Anyone can encrypt; only the holder can decrypt — or sign."),
    ("symmetric", "Symmetric", "Shared-key ciphers. Both sides hold the same key; fast enough for bulk data."),
    ("hash", "Hash & MAC", "One-way functions that fingerprint data and authenticate messages — the building blocks under almost every protocol."),
    ("pq", "Post-quantum", "Algorithms designed to survive an adversary with a large quantum computer."),
    ("hsm", "Key management & HSMs", "Patterns and devices for protecting the key material itself — vaults, not algorithms."),
]


def journey(request, bundle_slug):
    """Render a single bundle as a narrative essay — title, tagline, stations
    (per-algorithm prose), outro. Algorithms not currently live are skipped.
    Returns 404 if no bundle has the given slug."""
    from .bundles import BUNDLES
    import markdown as md_lib
    bundle = next((b for b in BUNDLES if b["slug"] == bundle_slug), None)
    if not bundle:
        from django.http import Http404
        raise Http404("journey not found")
    by_slug = {a.slug: a for a in Algorithm.objects.filter(status="live")}
    stations = []
    for st in bundle.get("stations", []):
        algo = by_slug.get(st["algorithm"])
        if not algo:
            continue
        stations.append({
            "algorithm": algo,
            "lesson_slug": algo.lessons.order_by("order").first().slug if algo.lessons.exists() else None,
            "prose_html": md_lib.markdown(st["prose"], extensions=["fenced_code", "tables"]),
        })
    return render(request, "core/journey.html", {
        "bundle": bundle,
        "stations": stations,
        "outro_html": md_lib.markdown(bundle.get("outro", ""), extensions=["fenced_code", "tables"]) if bundle.get("outro") else "",
    })


def landing(request):
    algorithms = list(Algorithm.objects.filter(status="live"))
    by_slug = {a.slug: a for a in algorithms}
    bundles = resolve_bundles(by_slug)

    # Group by family, preserving the FAMILY_SECTIONS order.
    grouped = OrderedDict()
    for family_key, family_label, family_blurb in FAMILY_SECTIONS:
        members = [a for a in algorithms if a.family == family_key]
        if not members:
            continue
        grouped[family_key] = {
            "label": family_label,
            "blurb": family_blurb,
            "algorithms": members,
        }

    return render(request, "core/landing.html", {
        "bundles": bundles,
        "family_sections": grouped,
    })


def algorithm_intro(request, slug):
    algorithm = get_object_or_404(Algorithm, slug=slug, status="live")
    lesson = algorithm.lessons.order_by("order").first()
    return render(request, "core/algorithm_intro.html", {
        "algorithm": algorithm,
        "lesson": lesson,
    })


def lesson_runner(request, algo_slug, lesson_slug):
    import markdown as md_lib
    algorithm = get_object_or_404(Algorithm, slug=algo_slug, status="live")
    lesson = get_object_or_404(Lesson, algorithm=algorithm, slug=lesson_slug)
    db_steps = list(lesson.steps.order_by("order"))
    progress = None
    state = {}
    current = 1
    if request.user.is_authenticated:
        progress, _ = UserProgress.objects.get_or_create(
            user=request.user, lesson=lesson,
            defaults={"current_step_order": 1, "state": {}},
        )
        state = progress.state or {}
        current = progress.current_step_order or 1

    # Render markdown only; leave `{{ state.X }}` placeholders intact so the
    # client substitutes live values from the wizard's reactive state.
    def render_md(template_str):
        return md_lib.markdown(
            template_str or "",
            extensions=["fenced_code", "tables"],
        )

    steps_payload = [
        {
            "order": s.order,
            "slug": s.slug,
            "kind": s.kind,
            "validator_key": s.validator_key,
            "codegen_key": s.codegen_key,
            "prompt_html": render_md(s.prompt_template),
            "help_html": render_md(s.help_template),
        }
        for s in db_steps
    ]

    return render(request, "core/lesson.html", {
        "algorithm": algorithm,
        "lesson": lesson,
        "progress": progress,
        "initial_data": {
            "algorithmSlug": algorithm.slug,
            "lessonSlug": lesson.slug,
            "steps": steps_payload,
            "state": state,
            "currentStepOrder": current,
            "loggedIn": request.user.is_authenticated,
        },
    })


@login_required
def dashboard(request):
    rows = UserProgress.objects.filter(user=request.user).select_related("lesson__algorithm")
    return render(request, "core/dashboard.html", {"rows": rows})
