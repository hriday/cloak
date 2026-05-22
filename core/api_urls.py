from django.urls import path
from . import api

urlpatterns = [
    path("progress/import/", api.progress_import, name="api_progress_import"),
    path("progress/<slug:algo_slug>/<slug:lesson_slug>/", api.progress_detail, name="api_progress_detail"),
]
