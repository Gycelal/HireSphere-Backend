from django.urls import path
from .views import RegisterView,LoginView,VerifyOTPView,ResendOTPView,ForgotPasswordView,ResetPasswordView

urlpatterns = [
    path('register/',RegisterView.as_view(),name='register'),
    path('login/',LoginView.as_view(),name='login'),
    path('verify-otp/',VerifyOTPView.as_view(),name='verify-otp'),
    path('resend-otp/',ResendOTPView.as_view(),name='resend-otp'),
    path('forgot-password/',ForgotPasswordView.as_view(),name='forgot-password'),
    path('reset-password/',ResetPasswordView.as_view(),name='reset-password'),
]