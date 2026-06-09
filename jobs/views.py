from django.shortcuts import render
from rest_framework import viewsets
from accounts.permissions import IsRecruiter, IsApprovedRecruiter
from .serializers import JobSerializer
from .models import Job
import logging
# Create your views here.

logger = logging.getLogger(__name__)


class JobViewSet(viewsets.ModelViewSet):
    queryset = Job.objects.all()
    serializer_class = JobSerializer
    
    def get_permissions(self):
        if self.action in ["create", "update", "partial_update", "destroy"]:
            permission_classes = [IsRecruiter, IsApprovedRecruiter]
        else:
            permission_classes = []

        return [permission() for permission in permission_classes]
    
    
    


