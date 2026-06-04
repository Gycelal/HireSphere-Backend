from .models import Candidate
from rest_framework import serializers
from accounts.models import User

CANDIDATE_PROFILE_FIELDS = [
    "headline",
    "qualification",
    "professional_skills",
    "experience_years",
    "profile_picture",
    "resume"
]

class CandidateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Candidate
        fields = CANDIDATE_PROFILE_FIELDS
    
    def validate_headline(self, value):
        value = value.strip()
        if value == "":
            return value
        if value.isdigit():
            raise serializers.ValidationError(
                "Headline cannot contain only numbers."
            )
        return value
    def validate_qualification(self, value):
        pass
    



class CandidateSerializer(serializers.ModelSerializer):
    profile = CandidateProfileSerializer(source='candidate', required=False)
    completion_percentage = serializers.SerializerMethodField()
    email = serializers.EmailField(read_only=True)
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "profile"]
    
    def get_completion_percentage(self, user):
        profile = getattr(user, "candidate", None)
        fields = [
            user.first_name,
            user.last_name,
            user.email,
        ]
        profile_fields = CANDIDATE_PROFILE_FIELDS
        if profile:
            fields.extend([getattr(profile, field) for field in profile_fields])
        else:
            fields.extend([None] * len(profile_fields)) 
        
        completed = sum(1 for field in fields if field)
        total = len(fields)
        return int((completed/total) * 100) if total > 0 else 0

    
    def update(self, user, validated_data):
        profile_data = validated_data.pop('candidate', {})

        # Save User model data
        for attr, value in validated_data.items():
            setattr(user, attr, value)
        user.save()

        profile, created = Candidate.objects.get_or_create(user=user)
        # save Candidate model data
        if profile_data:
            for attr, value in profile_data.items():
                setattr(profile, attr, value)
            profile.save()     
        return user     
    


    
    