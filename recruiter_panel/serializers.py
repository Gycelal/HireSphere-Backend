from rest_framework import serializers
from .models import RecruiterProfile


class RecruiterProfileSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source="user.first_name")
    last_name = serializers.CharField(source="user.last_name")
    email = serializers.EmailField(source="user.email", read_only=True)
    class Meta:
        model = RecruiterProfile
        fields = [
            "first_name",
            "last_name",
            "display_name",
            "profile_picture",
            "recruiter_type",
            "company_or_brand_name",
            "website_link",
            "location",
        ]

    def update(self, instance, validated_data):
        user_data = validated_data.pop("user", {})
        
        user = instance.user
        user.first_name = user_data.get("first_name", user.first_name)
        user.last_name = user_data.get("last_name", user.last_name)
        user.save()
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance