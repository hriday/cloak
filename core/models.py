from django.conf import settings
from django.db import models


class Algorithm(models.Model):
    FAMILY_CHOICES = [
        ("asymmetric", "Asymmetric"),
        ("symmetric", "Symmetric"),
        ("pq", "Post-Quantum"),
        ("hsm", "HSM"),
    ]
    STATUS_CHOICES = [
        ("live", "Live"),
        ("coming-soon", "Coming soon"),
    ]
    slug = models.SlugField(unique=True)
    name = models.CharField(max_length=80)
    family = models.CharField(max_length=20, choices=FAMILY_CHOICES)
    intro_template = models.CharField(max_length=200, blank=True, default="")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="coming-soon")
    order = models.IntegerField(default=0)

    class Meta:
        ordering = ["order", "name"]

    def __str__(self):
        return self.name


class Lesson(models.Model):
    algorithm = models.ForeignKey(Algorithm, on_delete=models.CASCADE, related_name="lessons")
    slug = models.SlugField()
    title = models.CharField(max_length=120)
    order = models.IntegerField(default=0)

    class Meta:
        ordering = ["order"]
        constraints = [
            models.UniqueConstraint(fields=["algorithm", "slug"], name="unique_lesson_slug_per_algo"),
        ]

    def __str__(self):
        return f"{self.algorithm.name} — {self.title}"


class Step(models.Model):
    KIND_CHOICES = [
        ("info", "Info"),
        ("input-numeric", "Numeric input"),
        ("input-multi", "Multi-numeric input"),
        ("input-text", "Text input"),
        ("choose-from-list", "Choose from list"),
    ]
    lesson = models.ForeignKey(Lesson, on_delete=models.CASCADE, related_name="steps")
    order = models.IntegerField()
    slug = models.SlugField()
    kind = models.CharField(max_length=20, choices=KIND_CHOICES)
    prompt_template = models.TextField()
    help_template = models.TextField(blank=True, default="")
    validator_key = models.CharField(max_length=80, blank=True, default="")
    codegen_key = models.CharField(max_length=80, blank=True, default="")

    class Meta:
        ordering = ["order"]
        constraints = [
            models.UniqueConstraint(fields=["lesson", "slug"], name="unique_step_slug_per_lesson"),
            models.UniqueConstraint(fields=["lesson", "order"], name="unique_step_order_per_lesson"),
        ]

    def __str__(self):
        return f"{self.lesson} :: {self.slug}"


class UserProgress(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="progress")
    lesson = models.ForeignKey(Lesson, on_delete=models.CASCADE)
    current_step_order = models.IntegerField(default=1)
    state = models.JSONField(default=dict)
    completed_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "user progress"
        verbose_name_plural = "user progress"
        constraints = [
            models.UniqueConstraint(fields=["user", "lesson"], name="unique_progress_per_user_lesson"),
        ]
