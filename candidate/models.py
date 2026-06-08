from django.db import models
from accounts.models import User
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MaxValueValidator

# Create your models here.



class Candidate(models.Model):
    user= models.OneToOneField(User, on_delete=models.CASCADE)
    headline = models.CharField(max_length=255, blank=True)
    qualification = models.CharField(max_length=255, blank=True)
    professional_skills = ArrayField(models.CharField(max_length=100, blank=True), blank=True, default=list)
    experience_years = models.PositiveIntegerField(default=0,validators=[MaxValueValidator(50)], blank=True)
    profile_picture = models.URLField(blank=True, null=True)
    profile_picture_public_id = models.CharField(max_length=255, blank=True, null=True)
    resume_url = models.URLField(blank=True, null=True)
    resume_public_id = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.user.first_name + " " + self.user.last_name