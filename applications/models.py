from django.db import models

# Create your models here.


class Application(models.Model):
    
    STATUS_CHOICES = [
    ("applied", "Applied"),
    ("shortlisted", "Shortlisted"),
    ("interviewing", "Interviewing"),
    ("rejected", "Rejected"),
    ("hired", "Hired"),
]
    
    candidate = models.ForeignKey("accounts.User", on_delete=models.CASCADE, related_name="applications")
    job = models.ForeignKey("jobs.Job", on_delete=models.CASCADE, related_name="applications")
    resume_url = models.URLField()
    cover_letter = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="applied")
    applied_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
        models.UniqueConstraint(
            fields = ["candidate", "job"],
            name = "unique_candidate_job_application"
        )
    ]


