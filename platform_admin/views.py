from django.shortcuts import render
from rest_framework.permissions import IsAdminUser
from rest_framework.viewsets import ModelViewSet
from accounts.models import User
from rest_framework import status
from rest_framework.response import Response
from .serializers import AdminRecruiterListSerializer, AdminRecruiterApprovalSerializer
from rest_framework.decorators import action
# Create your views here.

class AdminRecruiterViewSet(ModelViewSet):
    permission_classes = [IsAdminUser]

    from rest_framework.filters import SearchFilter
    filter_backends = [SearchFilter]
    search_fields = ["first_name", "last_name", "email", "company_name"]

    def get_queryset(self):    
        query_set = User.objects.filter(role="recruiter").order_by("-date_joined")
        status_param = self.request.query_params.get("status")

        if status_param:
            query_set = query_set.filter(approval_status=status_param)
        else:
            query_set = query_set.filter(approval_status="pending")

        return query_set
    
    def get_serializer_class(self):
        if self.action == "list":
            return AdminRecruiterListSerializer
        elif self.action == "approval":
            return AdminRecruiterApprovalSerializer

    def retrieve(self, request, pk=None):
        # Logic to retrieve a specific recruiter by pk
        pass

    @action(detail=True, methods=["patch"])
    def approval(self, request, pk=None):
        # Logic to approve a recruiter
        recruiter = self.get_object()

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        action_value = serializer.validated_data.get("action")
        if action_value == "approve":
            recruiter.approval_status = "approved"
        elif action_value == "reject":
            recruiter.approval_status = "rejected"
            recruiter.is_active = False

        recruiter.save()
        return Response({"message": f"Recruiter {action_value} successfully."}, status=status.HTTP_200_OK)
       
