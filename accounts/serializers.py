from rest_framework import serializers
from .models import User
from .utils import generate_otp, store_otp
from .tasks import send_verification_email
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer  
from .utils import validate_password
from django.core.cache import cache



class UserRegistrationSerializer(serializers.ModelSerializer):
    #  first_name, last_name, email, password, confirm_password, role

    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'confirm_password',  'role']
        read_only_fields = ['is_verified', 'is_approved']

    
    def validate(self, data):
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        validate_password(password, confirm_password)
        return data
    

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        password = validated_data.pop('password')

        if validated_data.get('role') == 'recruiter':
            validated_data['is_approved'] = False
        else:
            validated_data['is_approved'] = True

        user = User(**validated_data)
        user.set_password(password)
        user.save()

        otp = generate_otp()
        store_otp(user.id, otp)
        send_verification_email.delay(user.email, otp)


        return user
    


class LoginSerializer(TokenObtainPairSerializer):

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['email'] = user.email
        token['role'] = user.role
        return token
    

class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, data):
        token = data.get('token')
        user_id = cache.get(f"forgot_password_token:{token}")
        print(user_id)
        if not user_id:
            raise serializers.ValidationError({"token": "Invalid or expired token."})
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise serializers.ValidationError({"token": "User does not exist."})
        data['user'] = user
        data['token'] = token
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        validate_password(new_password, confirm_password)
        return data
    
    def save(self):
        user = self.validated_data['user']
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.save()
        token = self.validated_data['token']
        cache.delete(f"forgot_password_token:{token}")
    


    