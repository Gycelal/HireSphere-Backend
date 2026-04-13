from .models import Candidate
from rest_framework import serializers
from accounts.models import User

class CandidateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Candidate
        fields = ['headline', 'qualification', 'professional_skills', 'experience_years', 'profile_picture', 'resume']


class CandidateSerializer(serializers.ModelSerializer):
    profile = CandidateProfileSerializer(source='candidate', required=False)
    email = serializers.EmailField(read_only=True)
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "profile"]

    
    def update(self, user, validated_data):
        profile_data = validated_data.pop('candidate', {})

        user.first_name = validated_data.get('first_name', user.first_name)
        user.last_name = validated_data.get('last_name', user.last_name)
        user.save()

        profile, created = Candidate.objects.get_or_create(user=user)
        profile.headline = profile_data.get('headline', profile.headline)
        profile.qualification = profile_data.get('qualification', profile.qualification)
        profile.professional_skills = profile_data.get('professional_skills', profile.professional_skills)
        profile.experience_years = profile_data.get('experience_years', profile.experience_years)
        profile.profile_picture = profile_data.get('profile_picture', profile.profile_picture)
        profile.resume = profile_data.get('resume', profile.resume)
        profile.save()      
        return user     