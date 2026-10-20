from rest_framework import serializers
from .models import Application
from .exceptions import AlreadyApplied
from candidate.models import Resume
from jobs.models import Job
from django.utils import timezone


class ApplicationSerializer(serializers.ModelSerializer):
    job = serializers.PrimaryKeyRelatedField(
        queryset=Job.objects.all(),
        error_messages={
            "does_not_exist": (
                "The selected job is unavailable. "
                "Please choose another job."
            ),
            "incorrect_type": "Please provide a valid job ID"
        }
    )
    resume = serializers.PrimaryKeyRelatedField(
        queryset=Resume.objects.all(),
        error_messages={
            "does_not_exist":(
                "The seleced resume is unavailable. "
                "Please choose another resume."
            ),
            "incorrect_type": "Please provide a valid resume ID"
        }
    )

    def validate(self, attrs):
        candidate = self.context["request"].user.candidate
        job = attrs["job"]

        if attrs["resume"].candidate_id != candidate.id:
            raise serializers.ValidationError({
                "resume": "please select one of your own resumes."
            })
        
        if not job.is_active:
            raise serializers.ValidationError({
                "job": "This job is no longer accepting applications."
            })

        if job.application_deadline < timezone.localdate():
            raise serializers.ValidationError({
                "job": "The application deadline has passed."
            })

        if Application.objects.filter(
            candidate=candidate,
            job=attrs["job"],
        ).exists():
            raise AlreadyApplied
        
        return attrs

    
    class Meta:
        model = Application
        fields = [
            "id",
            "job",
            "candidate",
            "resume",
            "cover_letter",
            "status",
            "applied_at",
        ]
        read_only_fields = [
            "candidate",
            "status",
            "applied_at",
        ]
