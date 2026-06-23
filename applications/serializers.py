from rest_framework import serializers
from .models import Application


class ApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Application
        fields = [
            "job",
            "candidate",
            "resume_url",
            "cover_letter",
            "status",
            "applied_at",
        ]
        read_only_fields = [
            "candidate",
            "status",
            "applied_at",
        ]
