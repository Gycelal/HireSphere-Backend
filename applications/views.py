from django.shortcuts import render
from rest_framework.viewsets import ModelViewSet
from rest_framework.generics import ListAPIView
from .models import Application
from accounts.permissions import IsApprovedRecruiter, IsCandidate
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status
from rest_framework.mixins import (CreateModelMixin, RetrieveModelMixin, ListModelMixin)
from rest_framework.viewsets import GenericViewSet
from .serializers import ApplicationSerializer
# Create your views here.


class ApplicationViewSet(CreateModelMixin, RetrieveModelMixin, ListModelMixin, GenericViewSet):
    """
    Manages job applications.

    Candidates can create applications, view application details,
    and list their own applications. Recruiters can view applications
    submitted to their jobs and update application status through the
    custom status action.

    Access to application data is restricted using role-based queryset filtering.
    """
    
    serializer_class = ApplicationSerializer

    def get_queryset(self):

        role = self.request.user.role 

        if role == "candidate":
            return Application.objects.filter(candidate=self.request.user)
        
        if role == "recruiter":
            return Application.objects.filter(job__recruiter=self.request.user)
        
        return Application.objects.none()
    
    
    def get_permissions(self):

        if self.action == "status":
            return [IsApprovedRecruiter()]
        
        if self.action in ["list", "create"]:
            return [IsCandidate()]
        
        return super().get_permissions()
    
    
    def perform_create(self, serializer):
        serializer.save(candidate=self.request.user)

    
    @action(detail=True, methods=["patch"])
    def status(self, request, pk=None):
        application = self.get_object()
        
        new_status = request.data.get("status")
        valid_statuses = [choice[0] for choice in Application.STATUS_CHOICES]
        if new_status not in valid_statuses:
            return Response({"details":"Invalid Status."}, status=status.HTTP_400_BAD_REQUEST)
        
        application.status = new_status
        application.save(update_fields=["status"])

        return Response({
            "message": "Status Updated Successfully.",
            "status": application.status,
        })



class JobApplicationsListAPIView(ListAPIView):

    permission_classes = [IsApprovedRecruiter]
    serializer_class = ApplicationSerializer

    def get_queryset(self):
        job_id = self.kwargs["job_id"]

        return Application.objects.filter(job_id=job_id, job__recruiter=self.request.user)
