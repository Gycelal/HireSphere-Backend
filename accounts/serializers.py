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

User = get_user_model()

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
        user = CustomUser.objects.filter(email=email).first()

        if user:
            if user.is_verified:
                raise serializers.ValidationError("User with this email already exist.")

            self.context['unverified_user'] = user
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

        otp = generate_otp()
        store_otp(user.email,otp)

        send_otp_email.delay(user.email,otp)

        return user
    

class LoginSerializer(serializers.Serializer):
    
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    
    def validate(self,data):
        email = data.get('email')
        password = data.get('password')

        validate_email_exists(email=email,should_exist=True)

        user = authenticate(email=email,password=password)

        if not user:
            raise serializers.ValidationError('Invalid Email or Password.')
        
        if not user.is_active:
            raise serializers.ValidationError('Account is Disabled.')
        
        if user.role in ['company_admin','company_member']:
            if not hasattr(user, 'company') or not user.company.is_approved:
                raise serializers.ValidationError("Your company account is not approved by the admin yet.")


        
        refresh = RefreshToken.for_user(user)

        return {
            'refresh':str(refresh),
            'access':str(refresh.access_token),
            'role':user.role,
        }
    

class OTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()

    def validate(self, data):
        email = data['email']
        otp = data['otp']

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
    uidb64 = serializers.CharField()
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate_password(self,password):
        validate_password_strength(password)
        return password
    
    def validate(self,data):
        uidb64 = data.get('uidb64')
        token = data.get('token')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        validate_password_match(password,confirm_password)

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
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

        
        







