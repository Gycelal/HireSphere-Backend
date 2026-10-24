from django.db import models
from accounts.models import User
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MaxValueValidator
import uuid

# Create your models here.


class Candidate(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="candidate"
    )
    headline = models.CharField(max_length=255, blank=True)
    qualification = models.CharField(max_length=255, blank=True)
    professional_skills = ArrayField(
        models.CharField(max_length=100, blank=True), blank=True, default=list
    )
    experience_years = models.PositiveIntegerField(
        default=0, validators=[MaxValueValidator(50)], blank=True
    )
    profile_picture = models.URLField(blank=True, null=True)
    profile_picture_public_id = models.CharField(max_length=255, blank=True, null=True)
    default_resume = models.OneToOneField(
        "Resume",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="default_candidate",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.user.first_name + " " + self.user.last_name


class Resume(models.Model):
    candidate = models.ForeignKey(
        Candidate, on_delete=models.CASCADE, related_name="resumes"
    )

    file_url = models.URLField()
    public_id = models.CharField(max_length=255)
    file_name = models.CharField(max_length=255)
    file_hash = models.CharField(max_length=64, null=True, blank=True, editable=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["candidate", "file_hash"],
                name="unique_candidate_resume_hash",
            )
        ]

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.candidate.user.email} - {self.file_name}"


class ResumeUploadAttempt(models.Model):
    class Purpose(models.TextChoices):
        PROFILE = "profile"
        APPLICATION = "application"

    class State(models.TextChoices):
        PENDING = "pending"
        SAVED = "saved"
        ABANDONED = "abandoned"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    candidate = models.ForeignKey(
        Candidate, on_delete=models.PROTECT, related_name="resume_upload_attempts"
    )
    purpose = models.CharField(max_length=20, choices=Purpose.choices)
    key = models.UUIDField()

    # Verify that retries use the same filename and file contents.
    fingerprint = models.CharField(max_length=64)

    # Reserve the Cloudinary asset ID before uploading, enabling cleanup.
    public_id = models.CharField(max_length=255, unique=True)

    # Reserved before uploading, so cleanup knows the asset ID even if the
    # cloudinary response never reaches the backend
    state = models.CharField(
        max_length=20, choices=State.choices, default=State.PENDING
    )

    # Foreignkey: different attemtps can reuse the same Resume.
    resume = models.ForeignKey(
        Resume,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="upload_attempts",
    )
    created_resume =models.BooleanField(default=False)

    cleanup_failures = models.PositiveIntegerField(default=0)
    next_cleanup_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["candidate", "purpose", "key"],
                name="unique_candidate_resume_ upload_key"
            )
        ]
        indexes = [
            models.Index(fields=["state", "created_at"]),
            models.Index(fields=["state", "next_cleanup_at"])
        ]
