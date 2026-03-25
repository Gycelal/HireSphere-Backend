from rest_framework import generics
from .serializers import (
    UserRegistrationSerializer,
    LoginSerializer,
    ResetPasswordSerializer,
    GoogleAuthSerializer,
    UserSerializer,
    SetRoleSerializer,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from .utils import (
    get_stored_otp,
    delete_stored_otp,
    generate_otp,
    store_otp,
    get_otp_resend_count,
)
from .models import User
from .tasks import send_verification_email, send_forgot_password_email
from django.core.cache import cache
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
import uuid
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.conf import settings
import logging

# Create your views here.

logger = logging.getLogger(__name__)


class UserRegistrationView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = UserRegistrationSerializer

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        otp = generate_otp()
        logger.debug("OTP for %s is %s", user.email, otp)
        store_otp(user.id, otp)
        send_verification_email.delay(user.email, otp)

        data = {
            "message": "User registered successfully. Please check your email for the OTP to verify your account.",
            "user_id": user.id,
        }
        return Response(data, status=status.HTTP_201_CREATED)


class EmailVerificationView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request):
        user_id = request.data.get("user_id")
        otp_from_user = request.data.get("otp")
        if not user_id or not otp_from_user:
            return Response(
                {"error": "User ID and OTP are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )
        stored_otp = get_stored_otp(user_id)

        if not stored_otp:
            return Response(
                {"error": "OTP has expired or invalid."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if stored_otp == otp_from_user:
            delete_stored_otp(user_id)
            user.is_verified = True
            user.save()
            return Response(
                {"message": "Email verified successfully."}, status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST
            )


class ResendOTPView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request):
        user_id = request.data.get("user_id")
        print("yeah user got in the view:", user_id)
        if not user_id:
            return Response(
                {"error": "User ID is required."}, status=status.HTTP_400_BAD_REQUEST
            )
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )

        if user.is_verified:
            return Response(
                {"message": "Your email is already verified."},
                status=status.HTTP_200_OK,
            )

        count = get_otp_resend_count(user_id)
        if count >= 3:
            return Response(
                {
                    "error": "You have exceeded the maximum number of OTP resend attempts. Please try again later."
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        if count == 0:
            cache.set(f"otp:resend_count:{user_id}", 1, timeout=900)
        else:
            cache.incr(f"otp:resend_count:{user_id}")

        new_otp = generate_otp()
        print("new otp:", new_otp)
        store_otp(user_id, new_otp)
        send_verification_email.delay(user.email, new_otp)
        return Response(
            {"message": "The OTP has been shared to your mail."},
            status=status.HTTP_200_OK,
        )


class LoginView(TokenObtainPairView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.user
        tokens = serializer.validated_data

        refresh = tokens["refresh"]
        access = tokens["access"]

        response = Response(
            {
                "access": access,
                "user": {"id": user.id, "email": user.email, "role": user.role},
            }
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh,
            httponly=True,
            secure=False,
            samesite="Lax",
            # max_age=60 * 60 * 24 * 7,  # 7 days - match your JWT refresh lifetime
            # path="/",  # Entire site access
        )
        return response


class CookieTokenRefreshView(TokenRefreshView):

    def post(self, request):

        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            return Response(
                {"error": "Refresh token not provided."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            serializer = TokenRefreshSerializer(data={"refresh": refresh_token})
            serializer.is_valid(raise_exception=True)
        except TokenError:
            return Response(
                {"error": "Invalid refresh token."}, status=status.HTTP_401_UNAUTHORIZED
            )

        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class LogoutView(APIView):

    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            return Response(
                {"error": "Refresh token not provided."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return Response(
                {"error": "Invalid refresh token."}, status=status.HTTP_401_UNAUTHORIZED
            )
        response = Response(
            {"message": "Logged out successfully."}, status=status.HTTP_200_OK
        )
        response.delete_cookie("refresh_token")
        return response


class ForgotPasswordView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response(
                {"email": "Email is required."}, status=status.HTTP_400_BAD_REQUEST
            )
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {
                    "message": "If this email exists, a password reset link has been sent."
                },
                status=status.HTTP_200_OK,
            )
        limit_key = f"forgot_password_limit:{email}"
        count = cache.get(limit_key, 0)
        if count >= 3:
            return Response(
                {"error": "Too many requests. Pleas try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
        token = str(uuid.uuid4())
        cache.set(f"forgot_password_token:{token}", user.id, timeout=900)
        print(f"Generated token for {email}: {token}")
        send_forgot_password_email.delay(email, token)
        cache.set(limit_key, count + 1, timeout=90)

        return Response(
            {
                "message": "If this email exists a  password Reset Link has been sent to your email for password reset."
            },
            status=status.HTTP_200_OK,
        )


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "Password reset successfully."}, status=status.HTTP_200_OK
        )


class GoogleAuthView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = GoogleAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        google_token = serializer.validated_data["id_token"]

        try:
            # Verify Google ID token
            idinfo = id_token.verify_oauth2_token(
                google_token, google_requests.Request(), settings.GOOGLE_CLIENT_ID
            )

            email = idinfo.get("email")
            first_name = idinfo.get("given_name") or ""
            last_name = idinfo.get("family_name") or ""

            # Create user if not exists
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "first_name": first_name,
                    "last_name": last_name,
                    "role": None,
                    "is_verified": True,
                },
            )

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)

            # Serialize user
            user_data = UserSerializer(user).data

            response = Response(
                {
                    "success": True,
                    "message": "Google login successful.",
                    "user": user_data,
                    "access": access,
                },
                status=status.HTTP_200_OK,
            )

            # Set refresh token as HttpOnly cookie
            response.set_cookie(
                key="refresh_token",
                value=str(refresh),
                httponly=True,
                secure=False,
                samesite="Lax",
            )

            return response

        except ValueError:
            return Response(
                {"success": False, "error": "Invalid Google token."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class SetRoleView(APIView):

    def post(self, request):
        serializer = SetRoleSerializer(
            request.user,
            data=request.data,
            context={"request": request}
        )

        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response(
            {
                "success": True,
                "message": "Role set successfully.",
                "user": UserSerializer(user).data
            },
            status=status.HTTP_200_OK
        )

