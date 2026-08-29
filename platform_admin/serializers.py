from rest_framework import serializers
from accounts.models import User
from candidate.models import Candidate
from recruiter.models import RecruiterProfile
import logging

logger = logging.getLogger(__name__)

class AdminRecruiterListSerializer(serializers.ModelSerializer):
    """
    Serializer for the admin side Recruiter Listing endpoint.
    """
    
    class Meta:
        model = User
        fields = ["id", "first_name", "last_name", "email", "approval_status", "date_joined"]

class AdminRecruiterApprovalSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=["approve", "reject"])
    


class UserManagementListSerializer(serializers.ModelSerializer):
    """
    serializer for the admin user listing endpoint.

    includes core user information and exposes the recruiter's
    company_or_brand_name when the user has a recruiter role.
    """
    
    company_or_brand_name = serializers.SerializerMethodField()

    def get_company_or_brand_name(self, obj):
        if obj.role == "recruiter":
            return obj.recruiterprofile.company_or_brand_name
        return None

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "role",
            "is_active",
            "date_joined",
            "company_or_brand_name"
        ]


class CandidateProfileSerializer(serializers.ModelSerializer):
    """
    serializer for candidate profile details.
    """
    class Meta:
        model = Candidate
        fields = "__all__"

class RecruiterProfileSerializer(serializers.ModelSerializer):
    """
    serializer for recruiter profile details.
    """
    class Meta:
        model = RecruiterProfile
        fields = "__all__"

class UserManagementDetailSerializer(serializers.ModelSerializer):
    """
    serializer for the admin user detail endpoint.

    includes user information and the associated candidate or
    recruiter profile based on the users role.
    """

    profile = serializers.SerializerMethodField()

    def get_profile(self, obj):
        logger.info("role in get profile:",obj.role)
        if obj.role == "candidate":
            return CandidateProfileSerializer(obj.candidate).data
        if obj.role == "recruiter":
            return RecruiterProfileSerializer(obj.recruiterprofile).data
        return None
    
    
    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "role",
            "is_active",
            "date_joined",
            "profile",
            "approval_status"
        ]

class UserStatusSerializer(serializers.ModelSerializer):
    """
    Serializer for updating a user's active status.
    """
    class Meta:
        model = User
        fields = ["is_active"]

        