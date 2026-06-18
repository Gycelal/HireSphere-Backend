from django.db import models
from django.contrib.postgres.fields import ArrayField

# Create your models here.


class Job(models.Model):

    EMPLOYMENT_TYPES = [
        ("full_time", "Full Time"),
        ("part_time", "Part Time"),
        ("contract", "Contract"),
        ("internship", "Internship"),
        ("freelance", "Freelance"),
    ]

    WORK_MODES = [
        ("onsite", "Onsite"),
        ("remote", "Remote"),
        ("hybrid", "Hybrid"),
    ]


    recruiter = models.ForeignKey("recruiter.RecruiterProfile",on_delete=models.CASCADE,related_name="jobs")
    title = models.CharField(max_length=255)
    description = models.TextField()
    location = models.CharField(max_length=255)
    employment_type = models.CharField(max_length=20,choices=EMPLOYMENT_TYPES)
    work_mode = models.CharField(max_length=10,choices=WORK_MODES,)
    skills_required = ArrayField(models.CharField(max_length=100))
    responsibilities = ArrayField(models.CharField(max_length=255),blank=True,default=list)
    application_deadline = models.DateField()
    vacancies = models.PositiveIntegerField()
    experience_required = models.PositiveIntegerField(default=0,help_text="Years of experience required",)
    salary_min = models.PositiveIntegerField(null=True, blank=True)
    salary_max = models.PositiveIntegerField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title
