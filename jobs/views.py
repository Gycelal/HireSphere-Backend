from django.shortcuts import render
from rest_framework import viewsets
from accounts.permissions import IsRecruiter, IsApprovedRecruiter, HasRecruiterProfile
from .serializers import JobSerializer
from .models import Job
import logging
from rest_framework.exceptions import  PermissionDenied
from rest_framework.filters import SearchFilter, OrderingFilter
# Create your views here.

logger = logging.getLogger(__name__)


class JobViewSet(viewsets.ModelViewSet):
    queryset = Job.objects.all()
    serializer_class = JobSerializer

    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ["title", "employment_type", "location"]
    ordering_fields = ["created_at", "title"]

    def get_permissions(self):
        if self.action in ["create", "update", "partial_update", "destroy"]:
            permission_classes = [IsRecruiter, IsApprovedRecruiter, HasRecruiterProfile]
        else:
            permission_classes = []

        return [permission() for permission in permission_classes]

    # Dynamically filter queryset based on user role
    def get_queryset(self):

        user = self.request.user
        logger.info(f"User {user.username} is accessing job listings.")

        if user.role == "recruiter":
            logger.info(f"Recruiter {user.username} is accessing their job listings.")
            return Job.objects.filter(recruiter=user.recruiterprofile)
        
        return Job.objects.filter(is_active=True)
        
    
    def perform_create(self, serializer):
        
        serializer.save(recruiter=self.request.user.recruiterprofile)
    
    
    def perform_update(self, serializer):

        job = self.get_object()

        if job.recruiter != self.request.user.recruiterprofile:
            raise PermissionDenied("You do not have permission to update this job.")
        
        serializer.save()


    def perform_destroy(self, job):

        if job.recruiter != self.request.user.recruiterprofile:
            raise PermissionDenied("You do not have permission to delete this job.")
        
        job.is_active = False
        logger.info(f"Job {job.title} (ID: {job.id}) has been marked as inactive by recruiter {self.request.user.username}.")
        job.save()
    

