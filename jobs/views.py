from django.shortcuts import render
from rest_framework import viewsets
from accounts.permissions import IsRecruiter, IsApprovedRecruiter, HasRecruiterProfile
from .serializers import JobSerializer
from .models import Job
import logging
from rest_framework.exceptions import PermissionDenied
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework.permissions import AllowAny
from .filters import JobFilter

# Create your views here.

logger = logging.getLogger(__name__)


class JobViewSet(viewsets.ModelViewSet):
    queryset = Job.objects.all()
    serializer_class = JobSerializer
    filterset_class = JobFilter

    filter_backends = [SearchFilter, OrderingFilter, DjangoFilterBackend]
    search_fields = ["title", "skills_required"]
    ordering_fields = ["created_at", "title"]
    ordering = ["-created_at"]

    def get_permissions(self):
        if self.action in ["create", "update", "partial_update", "destroy"]:
            permission_classes = [IsRecruiter, IsApprovedRecruiter, HasRecruiterProfile]
        else:
            permission_classes = [AllowAny]

        return [permission() for permission in permission_classes]

    # Dynamically filter queryset based on user role
    def get_queryset(self):

        user = self.request.user
        status_params = self.request.query_params.get("status")

        jobs = Job.objects.all()

        role = getattr(user, "role", None)

        if role == "recruiter":
            jobs = jobs.filter(recruiter=user.recruiterprofile)

        if status_params and status_params == "true":
            jobs = jobs.filter(is_active="True")
        elif status_params == "false":
            jobs = jobs.filter(is_active="False")

        return jobs

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
        job.save()
