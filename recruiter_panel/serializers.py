from rest_framework import serializers
from accounts.models import User
from .models import RecruiterProfile
import re

RECRUITER_PROFILE_FIELDS = [
    "display_name",
    "profile_picture",
    "recruiter_type",
    "company_or_brand_name",
    "website_url",
    "location",
]
class RecruiterSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = RecruiterProfile
        fields = RECRUITER_PROFILE_FIELDS
    
    def validate_display_name(self, value):
        value = value.strip()
        if value == "":
            return value
        
        if value.isdigit():
            raise serializers.ValidationError(
                "Display name cannot contain only numbers."
            )

        if not re.match(r"^[A-Za-z0-9 ]+$", value):
            raise serializers.ValidationError(
                "Only letters, numbers, and spaces are allowed."
            )

        return value
    
    def validate_company_or_brand_name(self, value):
        value = value.strip()
        if value == "":
            return value

        if value.isdigit():
            raise serializers.ValidationError(
                "Company or brand name cannot contain only numbers."
            )

        if not re.match(r"^[A-Za-z0-9 .&-]+$", value):
            raise serializers.ValidationError(
                "Only letters, numbers, spaces, '.', '&', and '-' are allowed."
            )
        return value
    def validate_location(self, value):
        value = value.strip()
        if value == "":
            return value
        
        if value.isdigit():
            raise serializers.ValidationError(
                "Location cannot contain only numbers."
            )

        if not re.match(r"^[A-Za-z0-9 ,.-]+$", value):
            raise serializers.ValidationError(
                "Invalid characters in location."
            )

        return value

class RecruiterProfileSerializer(serializers.ModelSerializer):
    profile = RecruiterSerializer(source="recruiterprofile", required=False)
    completion_percentage = serializers.SerializerMethodField()
    email  = serializers.EmailField(read_only=True)

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
        profile_fields = RECRUITER_PROFILE_FIELDS
        if profile:
            fields.extend([getattr(profile, field) for field in profile_fields])
        else:
            fields.extend([None] * len(profile_fields)) 
        
        completed = sum(1 for field in fields if field)
        total = len(fields)
        return int((completed/total) * 100) if total > 0 else 0

    def update(self, user, validated_data):
        profile_data = validated_data.pop("recruiterprofile", None)
        for attr, value in validated_data.items():
            setattr(user, attr, value)
        user.save()
        if profile_data:
            profile, created = RecruiterProfile.objects.get_or_create(user=user)
            for attr, value in profile_data.items():
                setattr(profile, attr, value)
            profile.save()
        return user


    
    
