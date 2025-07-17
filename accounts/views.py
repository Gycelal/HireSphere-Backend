from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import RegistrationSerializer,LoginSerializer,OTPVerifySerializer,ForgotPasswordSerializer,ResetPasswordSerializer
from .utils.otp import generate_otp, store_otp, can_resend_otp
from .tasks import send_otp_email,send_password_reset_email
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes



class RegisterView(APIView):
    def post(self,request):
        print("Registering user...")
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            unverified_user = serializer.context.get('unverified_user')
            if unverified_user:
                otp = generate_otp()
                print('OTP:', otp)
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
        print("Verifying OTP...")
        serializer = OTPVerifySerializer(data=request.data)

        if serializer.is_valid():
            print('verified')
            return Response({'message': 'OTP verified successfully'})
        print('not verified')
        return Response(serializer.errors, status=400)




class ResendOTPView(APIView):
    def post(self,request):
        email = request.data.get('email')
        if not email:
            return Response({"non_field_errors":"Email is required."},status=400)
        if not can_resend_otp(email):
            return Response({"non_field_errors":"Please wait before requesting a new OTP."},status=429)
        
        otp = generate_otp()
        print('Resending OTP:', otp)
        store_otp(email, otp)
        send_otp_email.delay(email, otp)
        return Response({"message":"OTP resent successfully."})




class LoginView(APIView):
    
    def post(self,request):
        print("Logging in user...")
        serializer = LoginSerializer(data=request.data)
        
        if serializer.is_valid():
            refresh_token = serializer.context.get('refresh_token')
            access_token = serializer.validated_data['access_token']
            user_data = serializer.validated_data['user']

            response = Response({
                'access_token': access_token,
                'user': user_data
            }, status=200)      

            response.set_cookie(
                key='refresh_token',
                value=refresh_token,
                httponly=True,
                secure=True,
                samesite='Lax', 
                path='/api/token/refresh/',  
                max_age=7 * 24 * 60 * 60, 
            )
            return response
        return Response(serializer.errors,status=400)


class ForgotPasswordView(APIView):
    def post(self,request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            token = PasswordResetTokenGenerator().make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = f"http://localhost:5173/reset-password/{uid}/{token}"
            send_password_reset_email.delay(user.email,reset_url)
            return Response({'message':"Password reset link sent to your mail."},status=200)
        return Response(serializer.errors,status=400)



class ResetPasswordView(APIView):
    def post(self,request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message':'Password reset successful'},status=200)
        return Response(serializer.errors,status=400)







