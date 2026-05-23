from django.contrib import admin
from .models import Algorithm, Lesson, Step, UserProgress


@admin.register(Algorithm)
class AlgorithmAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "family", "status", "order")
    list_filter = ("family", "status")
    search_fields = ("name", "slug")
    ordering = ("order", "name")


@admin.register(Lesson)
class LessonAdmin(admin.ModelAdmin):
    list_display = ("title", "algorithm", "slug", "order")
    list_filter = ("algorithm",)
    search_fields = ("title", "slug")
    ordering = ("algorithm", "order")


@admin.register(Step)
class StepAdmin(admin.ModelAdmin):
    list_display = ("lesson", "order", "slug", "kind", "validator_key")
    list_filter = ("kind", "lesson__algorithm", "lesson")
    search_fields = ("slug", "prompt_template")
    ordering = ("lesson", "order")


@admin.register(UserProgress)
class UserProgressAdmin(admin.ModelAdmin):
    list_display = ("user_email", "lesson", "current_step_order", "completed", "updated_at")
    list_filter = ("lesson__algorithm", "lesson", "completed_at")
    search_fields = ("user__email", "user__username")
    ordering = ("-updated_at",)
    readonly_fields = ("updated_at",)

    @admin.display(description="user", ordering="user__email")
    def user_email(self, obj):
        return obj.user.email or obj.user.username

    @admin.display(boolean=True, description="completed")
    def completed(self, obj):
        return obj.completed_at is not None
