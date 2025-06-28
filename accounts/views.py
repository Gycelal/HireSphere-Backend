from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import RegistrationSerializer,LoginSerializer,OTPVerifySerializer
from .utils.otp import generate_otp, store_otp, can_resend_otp
from .tasks import send_otp_email



class RegisterView(APIView):
    def post(self,request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            unverified_user = serializer.context.get('unverified_user')

            if unverified_user:
                otp = generate_otp()
                store_otp(unverified_user.email,otp)
                send_otp_email.delay(unverified_user.email,otp)
                return Response(
                    {'message': 'You have already registered. Please verify your email.'},
                    status=status.HTTP_200_OK
                )
            
            serializer.save()
            return Response({'message':'User Registered Successfully! Please verify your email.'},status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    



class VerifyOTPView(APIView):
    def post(self,request):
        serializer = OTPVerifySerializer(data=request.data)

        if serializer.is_valid():
            return Response({'message': 'OTP verified successfully'})
        return Response(serializer.errors, status=400)




class ResendOTPView(APIView):
    def post(self,request):
        email = request.data.get('email')
        if not email:
            return Response({"error":"Email is required."},status=400)
        if not can_resend_otp(email):
            return Response({"error":"Please wait before requesting a new OTP."},status=429)
        
        otp = generate_otp()
        store_otp(email, otp)
        send_otp_email.delay(email, otp)
        return Response({"message":"OTP resent successfully."})




class LoginView(APIView):
    
    def post(self,request):
        print(request.data)
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.validated_data,status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    

    



