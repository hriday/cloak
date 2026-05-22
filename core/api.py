from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import Lesson, UserProgress
from .serializers import ProgressPayloadSerializer, ImportPayloadSerializer
from .progress_service import validate_state


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def progress_detail(request, lesson_slug):
    lesson = get_object_or_404(Lesson, slug=lesson_slug)
    if request.method == "GET":
        progress, _ = UserProgress.objects.get_or_create(
            user=request.user, lesson=lesson,
            defaults={"current_step_order": 1, "state": {}},
        )
        return Response({
            "state": progress.state,
            "current_step_order": progress.current_step_order,
        })

    serializer = ProgressPayloadSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    state = serializer.validated_data["state"]
    current = serializer.validated_data["current_step_order"]

    ok, err = validate_state(lesson.algorithm.slug, state)
    if not ok:
        return Response({"detail": err}, status=status.HTTP_400_BAD_REQUEST)

    progress, _ = UserProgress.objects.update_or_create(
        user=request.user, lesson=lesson,
        defaults={"state": state, "current_step_order": current},
    )
    return Response({"state": progress.state, "current_step_order": progress.current_step_order})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def progress_import(request):
    serializer = ImportPayloadSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    imported = []
    skipped = []
    for item in serializer.validated_data["items"]:
        try:
            lesson = Lesson.objects.get(slug=item["lesson_slug"])
        except Lesson.DoesNotExist:
            skipped.append(item["lesson_slug"])
            continue
        ok, _ = validate_state(lesson.algorithm.slug, item["state"])
        if not ok:
            skipped.append(item["lesson_slug"])
            continue
        existing = UserProgress.objects.filter(user=request.user, lesson=lesson).first()
        if existing and existing.current_step_order >= item["current_step_order"]:
            continue
        UserProgress.objects.update_or_create(
            user=request.user, lesson=lesson,
            defaults={"state": item["state"], "current_step_order": item["current_step_order"]},
        )
        imported.append(item["lesson_slug"])
    return Response({"imported": imported, "skipped": skipped})
