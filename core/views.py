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
    algorithm = get_object_or_404(Algorithm, slug=algo_slug, status="live")
    lesson = get_object_or_404(Lesson, algorithm=algorithm, slug=lesson_slug)
    steps = list(lesson.steps.order_by("order"))
    progress = None
    if request.user.is_authenticated:
        progress, _ = UserProgress.objects.get_or_create(
            user=request.user, lesson=lesson,
            defaults={"current_step_order": 1, "state": {}},
        )
    return render(request, "core/lesson.html", {
        "algorithm": algorithm,
        "lesson": lesson,
        "steps": steps,
        "progress": progress,
    })


@login_required
def dashboard(request):
    rows = UserProgress.objects.filter(user=request.user).select_related("lesson__algorithm")
    return render(request, "core/dashboard.html", {"rows": rows})
