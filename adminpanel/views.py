from django.shortcuts import render
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from .serializers import AdminLoginSerializer
from rest_framework.response import Response
from rest_framework import status
# Create your views here.




class AdminLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self,request):
        serializer = AdminLoginSerializer(data=request.data)
        if serializer.is_valid():
            access_token = serializer.validated_data['access_token']
            refresh_token = serializer.validated_data['refresh_token']
            user_data = serializer.validated_data['user']

            response = Response({
                'access_token':access_token,
                'user':user_data
            },status=200)
            
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