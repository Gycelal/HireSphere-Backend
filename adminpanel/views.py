from rest_framework.permissions import AllowAny,IsAdminUser
from rest_framework.views import APIView
from .serializers import AdminLoginSerializer,CompanySerializer
from rest_framework.response import Response
from rest_framework import status
from .utils import handle_logout
from accounts.models import Company
from accounts.constants import CompanyAdminApprovalStatus
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
    permission_classes  = [IsAdminUser]
    def post(self, request):
        return handle_logout(request)
    

class PendingCompaniesView(APIView):
    def get(self,request):
        pending_companies = Company.objects.all()
        serializer = CompanySerializer(pending_companies,many=True)
        return Response(serializer.data,status=200)


class UpdateCompanyApprovalStatusView(APIView):
    permission_classes = [IsAdminUser]
    def patch(self,request,company_id):
        print('in update view')
        try:
            company = Company.objects.get(id=company_id)
        except Company.DoesNotExist:
            return Response({"error":"Company not found."},status=status.HTTP_404_NOT_FOUND)
        
        new_status = request.data.get('status')
        print('new_status:',new_status)
        valid_status = [CompanyAdminApprovalStatus.APPROVED,CompanyAdminApprovalStatus.PENDING,CompanyAdminApprovalStatus.REJECTED]

        if new_status not in valid_status:
            return Response({"error": "Invalid status"}, status=status.HTTP_400_BAD_REQUEST)
        
        company.approval_status = new_status
        company.save()

        return Response({
            "message": f"Company {new_status} successfully",
            "company_id": company.id,
            "status": company.approval_status
        }, status=status.HTTP_200_OK)
        