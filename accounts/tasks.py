from celery import shared_task
from django.core.mail import send_mail
from decouple import config
from django.conf import settings


from_email = config("DEFAULT_FROM_EMAIL")
frontend_url = config("FRONTEND_BASE_URL")
expiry_minutes = settings.PASSWORD_RESET_TIMEOUT // 60


@shared_task
def send_verification_email(email, otp):
    subject = "Welcome to HireSphere! Verify Your Email"
    
    message = (
        f"Hi there!\n\n"
        f"Thank you for joining HireSphere. To get started, please verify your email address.\n\n"
        f"Your OTP is: {otp}\n\n"
        f"This OTP will expire in 1 minutes. If you did not sign up, please ignore this email.\n\n"
        f"Welcome aboard!\nThe HireSphere Team"
    )
    send_mail(subject, message, from_email, [email])


@shared_task
def send_forgot_password_email(email, token):
    subject = "HireSphere Password Reset Request"
    
    message = (
        f"Hi there!\n\n"
        f"We received a request to reset your password for your HireSphere account.\n\n"
        f"Use the following link to reset your password:\n"
        f"{frontend_url}/reset-password/{token}\n\n"
        f"This link will expire in {expiry_minutes} minutes. If you did not request a password reset, please ignore this email.\n\n"
        f"Stay safe,\nThe HireSphere Team"
    )
    send_mail(subject, message, from_email, [email])
