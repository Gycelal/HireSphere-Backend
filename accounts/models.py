from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
from django.conf import settings


class CustomUserManager(BaseUserManager):
    
    def create_user(self,email,password=None,role=None,**extra_fields):
        if not email:
            raise ValueError("The Email field must be set.")
        if not role:
            raise ValueError("The Role field must be set.")
        
        email = self.normalize_email(email)
        user = self.model(email=email,role=role,**extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self,email,password=None,role=None,**extra_fields):
        extra_fields.setdefault('role','admin')
        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_superuser',True)
        extra_fields.setdefault('is_active',True)
        extra_fields.setdefault('is_verified',True)
        return self.create_user(email,password,**extra_fields)



class CustomUser(AbstractBaseUser,PermissionsMixin):
     
     ROLE_CHOICES = [
        ('candidate', 'Candidate'),
        ('company_admin', 'Company Admin'),
        ('company_member', 'Company Member'),
        ('admin', 'Admin'),
    ]
     
     email = models.EmailField(unique=True)
     role = models.CharField(max_length=20,choices=ROLE_CHOICES,default='pending')
     is_social_account = models.BooleanField(default=False)
     is_profile_complete = models.BooleanField(default=False)
     is_active = models.BooleanField(default=True)
     is_blocked = models.BooleanField(default=False)
     is_verified = models.BooleanField(default=False)
     is_staff = models.BooleanField(default=False)
     date_joined = models.DateTimeField(default=timezone.now)

     USERNAME_FIELD = 'email'
     REQUIRED_FIELDS = ['role']

     objects = CustomUserManager()

     def __str__(self):
         return f"{self.email} ({self.role})"



class Company(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,related_name='company')
    company_name = models.CharField(max_length=255)
    registration_number = models.CharField(max_length=100,unique=True)
    is_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.company_name
    
    
class Candidate(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,related_name='candidate')
    name = models.CharField(max_length=255)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"