from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404
from .models import Algorithm, Lesson, UserProgress


def landing(request):
    algorithms = list(Algorithm.objects.filter(status="live"))
    return render(request, "core/landing.html", {"algorithms": algorithms})


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
        return md_lib.markdown(template_str or "")

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
