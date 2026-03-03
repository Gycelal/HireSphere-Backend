from rest_framework import serializers
from accounts.models import User

class AdminRecruiterListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "first_name", "last_name", "email", "approval_status", "date_joined"]

class AdminRecruiterApprovalSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=["approve", "reject"])
    