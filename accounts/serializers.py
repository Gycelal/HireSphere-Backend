from rest_framework import serializers
from .models import User
import re
from .utils import generate_otp, store_otp
from .tasks import send_verification_email
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer  



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

        if password != confirm_password:
            raise serializers.ValidationError({"confirm_password": "Password do not match."})
        
        
        if not re.search(r"\d", password):
            raise serializers.ValidationError({"password": "Password must contain at least one digit."})
        if not re.search(r"[A-Z]", password):
            raise serializers.ValidationError({"password": "Password must contain at least one uppercase letter."})
        
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

    