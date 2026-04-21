from django.db import models
from django.conf import settings

# Create your models here.


class RecruiterProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="recruiterprofile")
    display_name = models.CharField(max_length=255, blank=True)
    profile_picture = models.URLField(blank=True)
    recruiter_type = models.CharField(max_length=255, blank=True)
    company_or_brand_name = models.CharField(max_length=255, blank=True)
    website_url = models.URLField(blank=True)
    # subscription_plan = models.ForeignKey(on_delete=models.SET_NULL, null=True, blank=True, related_name="recruiterprofile")
    location = models.CharField(max_length=255, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.display_name