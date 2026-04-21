from rest_framework import serializers
from accounts.models import User
from .models import RecruiterProfile


class RecruiterProfileSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = RecruiterProfile
        fields = [
            "display_name",
            "profile_picture",
            "recruiter_type",
            "company_or_brand_name",
            "website_url",
            "location",
        ]
    
class UserProfileSerializer(serializers.ModelSerializer):
    profile = RecruiterProfileSerializer(source="recruiterprofile", required=False)
    completion_percentage = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "profile", "completion_percentage"]

    def get_completion_percentage(self, user):
        profile = getattr(user, "recruiterprofile", None)
        fields = [
            user.first_name,
            user.last_name,
            user.email,
        ]
        profile_fields = RecruiterProfileSerializer.Meta.fields
        if profile:
            fields.extend([getattr(profile, field) for field in profile_fields])
        else:
            fields.extend([None] * len(profile_fields)) 
        
        completed = sum(1 for field in fields if field)
        total = len(fields)
        return int((completed/total) * 100) if total > 0 else 0

    def update(self, user, validated_data):
        profile_data = validated_data.pop("recruiterprofile", None)
        
        # update user
        user.first_name = validated_data.get("first_name", user.first_name)
        user.last_name = validated_data.get("last_name", user.last_name)
        user.save()

        if profile_data:
            profile, created = RecruiterProfile.objects.get_or_create(user=user)

            serializer = RecruiterProfileSerializer(
                profile,
                data=profile_data,
                partial=True
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            user.recruiterprofile = profile
        # user.refresh_from_db()  # Refresh user instance to get updated profile data
        return user
    
