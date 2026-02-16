
from django.urls import path
from .views import UserRegistrationView,EmailVerificationView, ResendOTPView, LoginView, CookieTokenRefreshView, LogoutView


urlpatterns =[
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', CookieTokenRefreshView.as_view(), name='token_refresh'),
    path('register/', UserRegistrationView.as_view(), name='user_registration'),
    path('verify-email/', EmailVerificationView.as_view(), name='email_verification'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend_otp'),
    path('logout/', LogoutView.as_view(), name='logout'),
]