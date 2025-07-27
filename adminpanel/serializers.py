from rest_framework import serializers
from accounts.validators import get_and_authenticate_user
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.timezone import now


class AdminLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        user = get_and_authenticate_user(email=email,password=password)

        if not user.is_staff or not user.is_superuser:
            raise serializers.ValidationError('You are not authorized to access this panel.')
        
        user.last_login = now()
        user.save(update_fields=["last_login"])

        refresh = RefreshToken.for_user(user)

        return{
            'access_token':str(refresh.access_token),
            'refresh_token':str(refresh),
            'user':{
                'id':user.id,
                'email':user.email,
                'role':user.role
            }
        }