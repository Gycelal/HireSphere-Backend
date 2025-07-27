from django.shortcuts import render
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
# Create your views here.




class AdminLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self,request):
        