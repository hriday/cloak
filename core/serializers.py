from rest_framework import serializers
from .models import UserProgress


class ProgressPayloadSerializer(serializers.Serializer):
    state = serializers.JSONField()
    current_step_order = serializers.IntegerField(min_value=1)


class ImportItemSerializer(serializers.Serializer):
    lesson_slug = serializers.SlugField()
    state = serializers.JSONField()
    current_step_order = serializers.IntegerField(min_value=1)


class ImportPayloadSerializer(serializers.Serializer):
    items = ImportItemSerializer(many=True)
