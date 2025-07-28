from django.shortcuts import render
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from .serializers import AdminLoginSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

# Create your views here.




class AdminLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self,request):
        print('in admin login view')
        serializer = AdminLoginSerializer(data=request.data)
        if serializer.is_valid():
            access_token = serializer.validated_data['access_token']
            refresh_token = serializer.validated_data['refresh_token']
            user_data = serializer.validated_data['user']

            response = Response({
                'access_token':access_token,
                'user':user_data
            },status=status.HTTP_200_OK)

            response.set_cookie(
                key='refresh_token',
                value=refresh_token,
                httponly=True,
                secure=True,
                samesite='Lax', 
                path='/api/accounts/token/refresh/',  
                max_age=7 * 24 * 60 * 60, 
            )
            return response
        return Response(serializer.errors,status=400)
    

class AdminLogout(APIView):
    def post(self, request):
        #admin users only
        if not request.user.is_superuser or not request.user.is_staff:
            return Response({"detail": "You are not authorized."}, status=403)

        refresh_token = request.COOKIES.get('refresh_token')
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except TokenError:
                pass  # Token is invalid or already blacklisted

        response = Response({'detail': 'Admin logged out successfully.'}, status=200)
        response.delete_cookie('refresh_token')
        return response