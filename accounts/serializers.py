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
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .utils.otp import generate_otp, store_otp, verify_otp
from .tasks import send_otp_email
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator

import requests

User = get_user_model()

class RegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=CustomUser.ROLE_CHOICES)

    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)

    company_name = serializers.CharField(required=False, allow_blank=True)
    registration_number = serializers.CharField(
        required=False,
        allow_blank=True,
        )

    def validate_email(self,email):
        user = CustomUser.objects.filter(email=email).first()

        if user:
            if user.is_verified:
                raise serializers.ValidationError("This email is already registered.")

            self.context['unverified_user'] = user
        return email


    def validate_password(self,password):
        validate_password_strength(password)
        return password
    
    def validate_registration_number(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Registration number is required.")

        exists = Company.objects.filter(
            registration_number=value,
            user__is_verified=True
        ).exists()
        if exists:
            raise serializers.ValidationError("A company with this registration number already exists.")
        
        return value

    def validate(self, data):
        role = data.get('role')
        password = data.get('password')
        confirm_password = data.get('confirm_password')


        validate_password_match(password,confirm_password)

        if role == 'candidate':
            errors = {}
            if not data.get('first_name', '').strip():
                errors['first_name'] = ['First name is required.']

            if not data.get('last_name', '').strip():
                errors['last_name'] = ['Last name is required.']

            if errors:
                raise serializers.ValidationError(errors)

        elif role == 'company_admin':
            errors = {}
            company_name = data.get('company_name', '').strip()

            if not company_name:
                errors['company_name'] = ['Company name is required.']
            elif company_name.isdigit():
                errors['company_name'] = ['Company name cannot be only numbers.']
            elif Company.objects.filter(company_name__iexact=company_name).exists():
                errors['company_name'] = ['A company with this name already exists.']

            if errors:
                raise serializers.ValidationError(errors)

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

        user.is_profile_complete = True
        user.save()

        otp = generate_otp()
        print('OTP:', otp)
        store_otp(user.email,otp)
        send_otp_email.delay(user.email,otp)

        return user
    

class GoogleAuthSerializer(serializers.Serializer):
    access_token = serializers.CharField()

    def validate(self, data):
        access_token = data.get('access_token')
        print("Validating Google access token...")

        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        response = requests.get('https://www.googleapis.com/oauth2/v1/userinfo', headers=headers)

        if response.status_code != 200:
            raise serializers.ValidationError('Invalid access token.')
        user_info = response.json()
        google_email = user_info.get('email')

        try:
            user = CustomUser.objects.get(email=google_email)
            print('user already exist.')

            if user.registration_method != 'google':
                raise serializers.ValidationError("This email is registered using a different method. Login using password instead.")

            refresh_token = RefreshToken.for_user(user)
            self.context['refresh_token'] = refresh_token

            user_data = {
                'id': user.id,
                'email': user.email,
                'role': user.role,
            }
            return {
                'access_token': str(refresh_token.access_token),
                'user': user_data,
                'is_profile_complete': user.is_profile_complete
            }
        except CustomUser.DoesNotExist:
            user = CustomUser.objects.create_user(
                email=google_email,
                is_verified=True,
                registration_method='google'
            )

            user_data = {
                'id': user.id,
                'email': user.email,
                'role': user.role,
            }
            refresh_token = RefreshToken.for_user(user) 
            self.context['refresh_token'] = refresh_token
            
            return{
                'access_token': str(refresh_token.access_token),
                'is_profile_complete': user.is_profile_complete,
            }



class CompleteProfileSerializer(serializers.Serializer):
    role = serializers.ChoiceField(choices=['candidate', 'company_admin'])

    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)

    company_name = serializers.CharField(required=False, allow_blank=True)
    registration_number = serializers.CharField(required=False, allow_blank=True)

    def validate_registration_number(self, value):
        value = value.strip()
        if value:
            exists = Company.objects.filter(
                registration_number=value,
                user__is_verified=True
            ).exists()
            if exists:
                raise serializers.ValidationError("A company with this registration number already exists.")
        return value

    def validate(self, data):
        print('in validate and data is:',data)
        role = data.get('role')
        errors = {}

        if role == 'candidate':
            if not data.get('first_name', '').strip():
                errors['first_name'] = ['First name is required.']
            if not data.get('last_name', '').strip():
                errors['last_name'] = ['Last name is required.']

        elif role == 'company_admin':
            company_name = data.get('company_name', '').strip()
            if not company_name:
                errors['company_name'] = ['Company name is required.']
            elif company_name.isdigit():
                errors['company_name'] = ['Company name cannot be only numbers.']
            elif Company.objects.filter(company_name__iexact=company_name).exists():
                errors['company_name'] = ['A company with this name already exists.']

        if errors:
            raise serializers.ValidationError(errors)

        return data

    def create(self, validated_data):
        role = validated_data.pop('role')
        user = self.context['request'].user

        if role == 'candidate':
            first_name = validated_data.get('first_name')
            last_name = validated_data.get('last_name')
            user.role = 'candidate'
            user.is_profile_complete = True
            user.save()
            Candidate.objects.create(user=user,first_name=first_name,last_name=last_name)

        elif role == 'company_admin':
            company_name = validated_data.get('company_name')
            registration_number = validated_data.get('registration_number')

            user.role = 'company_admin'
            user.is_profile_complete = True
            user.save()
            Company.objects.create(
                user=user,
                company_name=company_name,
                registration_number=registration_number
            )

        return user


class LoginSerializer(serializers.Serializer):
    
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    
    def validate(self,data):
        email = data.get('email')
        password = data.get('password')

        validate_email_exists(email=email,should_exist=True)

        user = authenticate(email=email,password=password)
        print('User:', user)

        if not user:
            raise serializers.ValidationError('Invalid credentials.')
        
        if user.is_blocked:
            raise serializers.ValidationError('Your account has been blocked by admin')
        if not user.is_verified:
            raise serializers.ValidationError(detail={"detail": "Please verify your account by the OTP which has been sent to your email before logging in.", "code": "unverified_user"})

        if user.role in ['company_admin','company_member']:
            company = getattr(user, 'company', None)
            if not company or not company.is_approved:
                raise serializers.ValidationError("Your account has not been approved by the admin yet.")


        refresh_token = RefreshToken.for_user(user)
        self.context['refresh_token'] = refresh_token

        # Basic user info
        user_data = {
            'id':user.id,
            'email': user.email,
            'role': user.role,
        }
        # role specific info

        if user.role == 'candidate' and hasattr(user, 'candidate'):
            user_data['first_name'] = user.candidate.first_name
            user_data['last_name'] = user.candidate.last_name
        elif user.role in ['company_admin', 'company_member'] and hasattr(user, 'company'):
            user_data['company_name'] = user.company.company_name
            user_data['registration_number'] = user.company.registration_number

        return {
            'access_token': str(refresh_token.access_token),
            'user': user_data
        }    



class OTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()

    def validate(self, data):
        email = data['email'].strip()
        otp = data['otp'].strip()

        if not verify_otp(email, otp):
            raise serializers.ValidationError('Invalid or expired OTP.')
        

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")
        
        user.is_verified = True
        user.save(update_fields=['is_verified'])
        
        return data
    

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self,data):
        email = data.get('email')

        validate_email_exists(email=email,should_exist=True)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        if not user.is_verified:
            raise serializers.ValidationError('User Should verify the email first.')
        data['user'] = user
        return data

class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField()
    uid = serializers.CharField()
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate_password(self,password):
        validate_password_strength(password)
        return password
    
    def validate(self,data):
        uid = data.get('uid')
        token = data.get('token')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        validate_password_match(password,confirm_password)

        try:
            uid = urlsafe_base64_decode(uid).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid or expired token.")
        

        if not default_token_generator.check_token(user, token):
            raise serializers.ValidationError('Invalid or expired reset token.')
        
        self.user = user

        return data
    
    def save(self):
        password = self.validated_data['password']
        self.user.set_password(password)
        self.user.save()

        
        







