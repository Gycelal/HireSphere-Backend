from rest_framework import serializers
from .models import Job
from recruiter.models import RecruiterProfile
from django.utils import timezone

import logging

logger = logging.getLogger(__name__)


class JobRecruiterSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source="user.first_name", read_only=True)
    last_name = serializers.CharField(source="user.last_name", read_only=True)

    class Meta:
        model = RecruiterProfile
        fields = [
            "id",
            "display_name",
            "profile_picture",
            "company_or_brand_name",
            "first_name",
            "last_name"
        ]

class JobSerializer(serializers.ModelSerializer):
    recruiter = JobRecruiterSerializer(read_only=True)

    class Meta:
        model = Job
        fields = [
            "id",
            "title",
            "description",
            "location",
            "employment_type",
            "work_mode",
            "skills_required",
            "responsibilities",
            "application_deadline",
            "vacancies",
            "experience_required",
            "salary_min",
            "salary_max",
            "is_active",
            "created_at",
            "recruiter"
        ]

    def validate_title(self, value):
        value = value.strip()

        if not value:
            raise serializers.ValidationError("Title cannot be empty.")

        if len(value) < 5:
            raise serializers.ValidationError("Title must be at least 5 characters.")
        return value

    def validate_description(self, value):
        value = value.strip()

        if not value:
            raise serializers.ValidationError("Description cannot be empty.")

        if len(value) < 50:
            raise serializers.ValidationError(
                "Description must be at least 50 characters."
            )

        return value

    def validate_location(self, value):
        value = value.strip()

        if not value:
            raise serializers.ValidationError("Location cannot be empty.")

        if len(value) < 2:
            raise serializers.ValidationError("Location is too short.")

        return value

    def validate_salary_min(self, value):

        if value is not None and  value <= 0:
            raise serializers.ValidationError(
                "Minimum salary should be greater than zero."
            )
        return value

    def validate_salary_max(self, value):

        if value is not None and  value <= 0:
            raise serializers.ValidationError(
                "Maximum salary should be greater than zero."
            )
        return value

    def validate_skills_required(self, value):
        if not value:
            raise serializers.ValidationError("At least one skill is required.")

        for skill in value:
            if not skill.strip():
                raise serializers.ValidationError("Skills cannot be empty.")

        return value

    def validate_responsibilities(self, value):
        for responsibility in value:
            if not responsibility.strip():
                raise serializers.ValidationError(
                    "Responsibilities cannot contain empty items."
                )

        return value

    def validate_application_deadline(self, value):
        if value <= timezone.now().date():
            raise serializers.ValidationError(
                "Application deadline must be in the future."
            )
        return value

    def validate_vacancies(self, value):
        if value < 1:
            raise serializers.ValidationError("Vacancies must be at least 1.")
        return value

    def validate_experience_required(self, value):
        if value > 50:
            raise serializers.ValidationError("Experience cannot exceed 50 years.")
        return value

    def validate(self, attr):
        salary_min = attr.get("salary_min")
        salary_max = attr.get("salary_max")

        if (salary_min is None) != (salary_max is None):
            raise serializers.ValidationError(
                "Provide both minimum and maximum salary or leave both empty."
            )
        if salary_min is not None and salary_max is not None:
            if salary_min > salary_max:
                raise serializers.ValidationError(
                    "Minimum salary cannot be greater than maximum salary."
                )
        return attr
        
