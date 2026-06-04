from django.db import models
from accounts.models import User
from django.contrib.postgres.fields import ArrayField

# Create your models here.



class Candidate(models.Model):
    user= models.OneToOneField(User, on_delete=models.CASCADE)
    headline = models.CharField(max_length=255, blank=True)
    qualification = models.CharField(max_length=255, blank=True)
    professional_skills = ArrayField(models.CharField(max_length=50), blank=True, default=list)
    experience_years = models.FloatField(default=0)
    profile_picture = models.URLField(blank=True)
    profile_picture_public_id = models.CharField(max_length=255, blank=True)
    resume = models.URLField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.user.first_name + " " + self.user.last_name