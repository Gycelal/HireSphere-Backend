from rest_framework import serializers
from .models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer  
from .utils import validate_password
from django.core.cache import cache



class UserRegistrationSerializer(serializers.ModelSerializer):

    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'confirm_password',  'role']
        extra_kwargs= {
            "email": {"validators": []}
        }
        read_only_fields = ['is_verified', 'approval_status']

    
    def validate(self, data):
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        validate_password(password, confirm_password)
        return data
    
    def validate_email(self, value):
        return value.lower()
        

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        password = validated_data.pop('password')
        email = validated_data.pop('email')

        user = User.objects.filter(email=email).first()

        # Existing User case 
        if user:
            if user.is_verified:
                raise serializers.ValidationError(
                    {"email": "User with this email already exist."}
                )
            # exists but not verified
            else:
                user.set_password(password)
                for attr, value in validated_data.items():
                    setattr(user, attr, value)
                
                if validated_data.get('role') == 'recruiter':
                    validated_data['approval_status'] = "pending"
                user.save()
                return user
        # new user
        if validated_data.get('role') == 'recruiter':
            validated_data['approval_status'] = "pending"

        user = User.objects.create_user(
            password=password,
            email=email,
            **validated_data
        )

        return user

class LoginSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        if not self.user.is_verified:
            raise serializers.ValidationError({"detail": "Email not verified. Please verify your email before logging in."})
        return data
    

class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        print("validating passwords")
        token = data.get('token')
        user_id = cache.get(f"forgot_password_token:{token}")
        print(user_id)
        if not user_id:
            raise serializers.ValidationError({"error": "Invalid or expired token."})
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise serializers.ValidationError({"error": "User does not exist."})
        password = data.get('password')
        # whether the new password is same as the old password
        if user.check_password(password):
            print("Same password")
            raise serializers.ValidationError({
                "password": "New password cannot be the same as the old password."
            })
        
        data['user'] = user
        data['token'] = token
        confirm_password = data.get('confirm_password')
        validate_password(password, confirm_password)
        return data
    
    def save(self):
        print("saving passwords")
        user = self.validated_data['user']
        password = self.validated_data['password']
        user.set_password(password)
        user.save()
        token = self.validated_data['token']
        cache.delete(f"forgot_password_token:{token}")

class GoogleAuthSerializer(serializers.Serializer):
    id_token = serializers.CharField()
    

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "role",
        ]


    