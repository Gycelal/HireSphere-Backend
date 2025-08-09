from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from .serializers import AdminLoginSerializer,CompanySerializer
from rest_framework.response import Response
from rest_framework import status
from .utils import handle_logout
from accounts.models import Company
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


class AdminLogoutView(APIView):
    def post(self, request):
        #admin users only
        if not request.user.is_superuser or not request.user.is_staff:
            return Response({"detail": "You are not authorized."}, status=403)

        return handle_logout(request)
    

class PendingCompaniesView(APIView):
    def get(self,request):
        pending_companies = Company.objects.filter(is_approved=False)
        serializer = CompanySerializer(pending_companies,many=True)
        return Response(serializer.data,status=200)