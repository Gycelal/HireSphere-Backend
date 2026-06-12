from rest_framework import serializers
from accounts.models import User
from candidate.models import Candidate
from recruiter.models import RecruiterProfile

class AdminRecruiterListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "first_name", "last_name", "email", "approval_status", "date_joined"]

class AdminRecruiterApprovalSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=["approve", "reject"])
    


class UserManagementListSerializer(serializers.ModelSerializer):

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
        ]
class CandidateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Candidate
        fields = "__all__"

class RecruiterProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecruiterProfile
        fields = "__all__"

class UserManagementDetailSerializer(serializers.ModelSerializer):
    profile = serializers.SerializerMethodField()

    def get_profile(self, obj):
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
            "profile"
        ]

class UserStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["is_active"]

        