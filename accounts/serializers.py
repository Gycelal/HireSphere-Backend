from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Company , Candidate
from .models import CustomUser
from .validators import (
    validate_password_strength,
    validate_password_match,
    validate_email_exists,
)
from rest_framework.validators import UniqueValidator




class RegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=CustomUser.ROLE_CHOICES)
    
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)

    company_name =serializers.CharField(required=False)
    registration_number = serializers.CharField(
    required=False,
    validators=[
        UniqueValidator(
            queryset=Company.objects.all(),
            message="A company with this registration number already exists."
        )
    ]
)

    def validate_email(self,email):
        validate_email_exists(email,should_exist=False)
        return email
    
    def validate_password(self,password):
        validate_password_strength(password)
        return password
    
    

    def validate(self, data):
        role = data.get('role')
        password = data.get('password')
        confirm_password = data.get('confirm_password')


        validate_password_match(password,confirm_password)

        if role == 'candidate':
            if not data.get('first_name') or not data.get('last_name'):
                raise serializers.ValidationError('Both first name and last name are required for candidates.')

        elif role == 'company_admin':
            if not data.get('company_name') or not data.get('registration_number'):
                raise serializers.ValidationError('Company name and registration number are required for company admins.')

        return data
    
    def create(self,validated_data):
        role = validated_data.pop('role')
        password = validated_data.pop('password')
        

        user = CustomUser.objects.create_user(email=validated_data['email'],password=password,role=role)

        if role == 'candidate':
            first_name = validated_data.pop('first_name')
            last_name = validated_data.pop('last_name')
            Candidate.objects.create(user=user, first_name=first_name, last_name=last_name)

        elif role == 'company_admin':
            company_name = validated_data.pop('company_name')
            registration_number = validated_data.pop('registration_number')
            Company.objects.create(user=user, company_name=company_name, registration_number=registration_number)
        
        validated_data.pop('confirm_password', None)

        return user