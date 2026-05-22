from django.contrib import admin
from .models import Algorithm, Lesson, Step, UserProgress

admin.site.register(Algorithm)
admin.site.register(Lesson)
admin.site.register(Step)
admin.site.register(UserProgress)
