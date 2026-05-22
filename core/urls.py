from django.urls import path
from . import views

urlpatterns = [
    path("", views.landing, name="landing"),
    path("algorithms/<slug:slug>/", views.algorithm_intro, name="algorithm_intro"),
    path("algorithms/<slug:algo_slug>/learn/<slug:lesson_slug>/", views.lesson_runner, name="lesson_runner"),
    path("me/progress/", views.dashboard, name="dashboard"),
]
